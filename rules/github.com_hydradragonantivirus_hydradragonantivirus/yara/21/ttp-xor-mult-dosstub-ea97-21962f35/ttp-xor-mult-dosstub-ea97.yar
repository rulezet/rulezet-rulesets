rule TTP_XOR_MULT_DOSStub_ea97 {
  strings:
    $key_ea97 = { be ff [2] ca e7 [2] 8d e5 [2] ca f4 [2] 84 f8 [2] 88 f2 [2] 9f f9 [2] 84 b7 [2] b9 }

  condition:
    any of them
}