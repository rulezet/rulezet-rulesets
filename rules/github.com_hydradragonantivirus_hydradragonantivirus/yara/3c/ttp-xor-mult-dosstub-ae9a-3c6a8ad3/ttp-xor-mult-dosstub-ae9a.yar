rule TTP_XOR_MULT_DOSStub_ae9a {
  strings:
    $key_ae9a = { fa f2 [2] 8e ea [2] c9 e8 [2] 8e f9 [2] c0 f5 [2] cc ff [2] db f4 [2] c0 ba [2] fd }

  condition:
    any of them
}