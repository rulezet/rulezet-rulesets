rule TTP_XOR_MULT_DOSStub_ae49 {
  strings:
    $key_ae49 = { fa 21 [2] 8e 39 [2] c9 3b [2] 8e 2a [2] c0 26 [2] cc 2c [2] db 27 [2] c0 69 [2] fd }

  condition:
    any of them
}