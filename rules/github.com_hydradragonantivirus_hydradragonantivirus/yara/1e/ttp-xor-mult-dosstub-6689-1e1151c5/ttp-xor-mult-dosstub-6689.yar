rule TTP_XOR_MULT_DOSStub_6689 {
  strings:
    $key_6689 = { 32 e1 [2] 46 f9 [2] 01 fb [2] 46 ea [2] 08 e6 [2] 04 ec [2] 13 e7 [2] 08 a9 [2] 35 }

  condition:
    any of them
}