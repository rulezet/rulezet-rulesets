rule TTP_XOR_MULT_DOSStub_ae4e {
  strings:
    $key_ae4e = { fa 26 [2] 8e 3e [2] c9 3c [2] 8e 2d [2] c0 21 [2] cc 2b [2] db 20 [2] c0 6e [2] fd }

  condition:
    any of them
}