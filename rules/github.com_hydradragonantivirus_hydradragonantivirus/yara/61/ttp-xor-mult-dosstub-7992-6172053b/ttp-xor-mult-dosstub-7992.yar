rule TTP_XOR_MULT_DOSStub_7992 {
  strings:
    $key_7992 = { 2d fa [2] 59 e2 [2] 1e e0 [2] 59 f1 [2] 17 fd [2] 1b f7 [2] 0c fc [2] 17 b2 [2] 2a }

  condition:
    any of them
}