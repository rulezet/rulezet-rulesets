rule TTP_XOR_MULT_DOSStub_ae2d {
  strings:
    $key_ae2d = { fa 45 [2] 8e 5d [2] c9 5f [2] 8e 4e [2] c0 42 [2] cc 48 [2] db 43 [2] c0 0d [2] fd }

  condition:
    any of them
}