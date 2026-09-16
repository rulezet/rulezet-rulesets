rule TTP_XOR_MULT_DOSStub_ae48 {
  strings:
    $key_ae48 = { fa 20 [2] 8e 38 [2] c9 3a [2] 8e 2b [2] c0 27 [2] cc 2d [2] db 26 [2] c0 68 [2] fd }

  condition:
    any of them
}