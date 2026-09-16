rule TTP_XOR_MULT_DOSStub_ae4d {
  strings:
    $key_ae4d = { fa 25 [2] 8e 3d [2] c9 3f [2] 8e 2e [2] c0 22 [2] cc 28 [2] db 23 [2] c0 6d [2] fd }

  condition:
    any of them
}