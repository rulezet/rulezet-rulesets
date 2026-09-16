rule TTP_XOR_MULT_DOSStub_ae12 {
  strings:
    $key_ae12 = { fa 7a [2] 8e 62 [2] c9 60 [2] 8e 71 [2] c0 7d [2] cc 77 [2] db 7c [2] c0 32 [2] fd }

  condition:
    any of them
}