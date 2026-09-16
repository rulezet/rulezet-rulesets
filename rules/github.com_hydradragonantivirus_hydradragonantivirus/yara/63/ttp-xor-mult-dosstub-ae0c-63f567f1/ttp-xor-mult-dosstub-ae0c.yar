rule TTP_XOR_MULT_DOSStub_ae0c {
  strings:
    $key_ae0c = { fa 64 [2] 8e 7c [2] c9 7e [2] 8e 6f [2] c0 63 [2] cc 69 [2] db 62 [2] c0 2c [2] fd }

  condition:
    any of them
}