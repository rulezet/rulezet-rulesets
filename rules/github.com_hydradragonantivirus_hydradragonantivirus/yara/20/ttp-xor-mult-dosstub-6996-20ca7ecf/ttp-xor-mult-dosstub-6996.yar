rule TTP_XOR_MULT_DOSStub_6996 {
  strings:
    $key_6996 = { 3d fe [2] 49 e6 [2] 0e e4 [2] 49 f5 [2] 07 f9 [2] 0b f3 [2] 1c f8 [2] 07 b6 [2] 3a }

  condition:
    any of them
}