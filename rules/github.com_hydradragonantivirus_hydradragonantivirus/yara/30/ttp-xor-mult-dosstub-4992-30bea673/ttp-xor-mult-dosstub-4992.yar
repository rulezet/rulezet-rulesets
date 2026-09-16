rule TTP_XOR_MULT_DOSStub_4992 {
  strings:
    $key_4992 = { 1d fa [2] 69 e2 [2] 2e e0 [2] 69 f1 [2] 27 fd [2] 2b f7 [2] 3c fc [2] 27 b2 [2] 1a }

  condition:
    any of them
}