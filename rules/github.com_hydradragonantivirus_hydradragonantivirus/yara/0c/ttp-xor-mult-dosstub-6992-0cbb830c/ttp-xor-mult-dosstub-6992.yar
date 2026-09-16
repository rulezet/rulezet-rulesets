rule TTP_XOR_MULT_DOSStub_6992 {
  strings:
    $key_6992 = { 3d fa [2] 49 e2 [2] 0e e0 [2] 49 f1 [2] 07 fd [2] 0b f7 [2] 1c fc [2] 07 b2 [2] 3a }

  condition:
    any of them
}