rule TTP_XOR_MULT_DOSStub_ae90 {
  strings:
    $key_ae90 = { fa f8 [2] 8e e0 [2] c9 e2 [2] 8e f3 [2] c0 ff [2] cc f5 [2] db fe [2] c0 b0 [2] fd }

  condition:
    any of them
}