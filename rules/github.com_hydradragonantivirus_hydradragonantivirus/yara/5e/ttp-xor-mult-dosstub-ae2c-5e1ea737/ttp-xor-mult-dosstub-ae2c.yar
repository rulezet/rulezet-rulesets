rule TTP_XOR_MULT_DOSStub_ae2c {
  strings:
    $key_ae2c = { fa 44 [2] 8e 5c [2] c9 5e [2] 8e 4f [2] c0 43 [2] cc 49 [2] db 42 [2] c0 0c [2] fd }

  condition:
    any of them
}