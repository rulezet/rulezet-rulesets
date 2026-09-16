rule TTP_XOR_MULT_DOSStub_0193 {
  strings:
    $key_0193 = { 55 fb [2] 21 e3 [2] 66 e1 [2] 21 f0 [2] 6f fc [2] 63 f6 [2] 74 fd [2] 6f b3 [2] 52 }

  condition:
    any of them
}