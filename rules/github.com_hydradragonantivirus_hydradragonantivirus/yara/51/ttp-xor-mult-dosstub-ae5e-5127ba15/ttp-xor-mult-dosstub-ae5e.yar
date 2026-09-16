rule TTP_XOR_MULT_DOSStub_ae5e {
  strings:
    $key_ae5e = { fa 36 [2] 8e 2e [2] c9 2c [2] 8e 3d [2] c0 31 [2] cc 3b [2] db 30 [2] c0 7e [2] fd }

  condition:
    any of them
}