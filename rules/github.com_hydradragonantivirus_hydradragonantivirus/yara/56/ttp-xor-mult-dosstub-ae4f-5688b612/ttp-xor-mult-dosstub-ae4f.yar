rule TTP_XOR_MULT_DOSStub_ae4f {
  strings:
    $key_ae4f = { fa 27 [2] 8e 3f [2] c9 3d [2] 8e 2c [2] c0 20 [2] cc 2a [2] db 21 [2] c0 6f [2] fd }

  condition:
    any of them
}