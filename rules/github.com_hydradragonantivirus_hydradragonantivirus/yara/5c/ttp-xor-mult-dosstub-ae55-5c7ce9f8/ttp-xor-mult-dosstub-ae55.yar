rule TTP_XOR_MULT_DOSStub_ae55 {
  strings:
    $key_ae55 = { fa 3d [2] 8e 25 [2] c9 27 [2] 8e 36 [2] c0 3a [2] cc 30 [2] db 3b [2] c0 75 [2] fd }

  condition:
    any of them
}