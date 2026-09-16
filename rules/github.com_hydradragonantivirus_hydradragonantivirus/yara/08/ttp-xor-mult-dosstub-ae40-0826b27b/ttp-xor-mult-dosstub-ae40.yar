rule TTP_XOR_MULT_DOSStub_ae40 {
  strings:
    $key_ae40 = { fa 28 [2] 8e 30 [2] c9 32 [2] 8e 23 [2] c0 2f [2] cc 25 [2] db 2e [2] c0 60 [2] fd }

  condition:
    any of them
}