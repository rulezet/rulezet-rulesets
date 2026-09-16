rule TTP_XOR_MULT_DOSStub_ae52 {
  strings:
    $key_ae52 = { fa 3a [2] 8e 22 [2] c9 20 [2] 8e 31 [2] c0 3d [2] cc 37 [2] db 3c [2] c0 72 [2] fd }

  condition:
    any of them
}