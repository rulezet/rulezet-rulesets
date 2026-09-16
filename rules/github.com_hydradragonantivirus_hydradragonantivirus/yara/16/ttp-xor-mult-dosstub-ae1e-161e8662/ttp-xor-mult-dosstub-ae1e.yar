rule TTP_XOR_MULT_DOSStub_ae1e {
  strings:
    $key_ae1e = { fa 76 [2] 8e 6e [2] c9 6c [2] 8e 7d [2] c0 71 [2] cc 7b [2] db 70 [2] c0 3e [2] fd }

  condition:
    any of them
}