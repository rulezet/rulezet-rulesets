rule TTP_XOR_MULT_DOSStub_ae3d {
  strings:
    $key_ae3d = { fa 55 [2] 8e 4d [2] c9 4f [2] 8e 5e [2] c0 52 [2] cc 58 [2] db 53 [2] c0 1d [2] fd }

  condition:
    any of them
}