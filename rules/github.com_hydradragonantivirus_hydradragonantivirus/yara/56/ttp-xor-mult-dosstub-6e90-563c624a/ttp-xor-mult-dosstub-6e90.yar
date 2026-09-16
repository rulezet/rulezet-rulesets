rule TTP_XOR_MULT_DOSStub_6e90 {
  strings:
    $key_6e90 = { 3a f8 [2] 4e e0 [2] 09 e2 [2] 4e f3 [2] 00 ff [2] 0c f5 [2] 1b fe [2] 00 b0 [2] 3d }

  condition:
    any of them
}