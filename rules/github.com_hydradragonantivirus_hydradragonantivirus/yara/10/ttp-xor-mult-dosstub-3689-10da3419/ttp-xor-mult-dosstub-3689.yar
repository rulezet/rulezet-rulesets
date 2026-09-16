rule TTP_XOR_MULT_DOSStub_3689 {
  strings:
    $key_3689 = { 62 e1 [2] 16 f9 [2] 51 fb [2] 16 ea [2] 58 e6 [2] 54 ec [2] 43 e7 [2] 58 a9 [2] 65 }

  condition:
    any of them
}