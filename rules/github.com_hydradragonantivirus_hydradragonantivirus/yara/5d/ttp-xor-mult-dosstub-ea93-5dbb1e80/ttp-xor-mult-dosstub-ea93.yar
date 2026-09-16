rule TTP_XOR_MULT_DOSStub_ea93 {
  strings:
    $key_ea93 = { be fb [2] ca e3 [2] 8d e1 [2] ca f0 [2] 84 fc [2] 88 f6 [2] 9f fd [2] 84 b3 [2] b9 }

  condition:
    any of them
}