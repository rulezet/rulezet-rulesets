rule TTP_XOR_MULT_DOSStub_2689 {
  strings:
    $key_2689 = { 72 e1 [2] 06 f9 [2] 41 fb [2] 06 ea [2] 48 e6 [2] 44 ec [2] 53 e7 [2] 48 a9 [2] 75 }

  condition:
    any of them
}