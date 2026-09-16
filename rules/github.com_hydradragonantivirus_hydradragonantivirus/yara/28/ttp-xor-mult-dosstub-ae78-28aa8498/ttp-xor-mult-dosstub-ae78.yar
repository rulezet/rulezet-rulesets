rule TTP_XOR_MULT_DOSStub_ae78 {
  strings:
    $key_ae78 = { fa 10 [2] 8e 08 [2] c9 0a [2] 8e 1b [2] c0 17 [2] cc 1d [2] db 16 [2] c0 58 [2] fd }

  condition:
    any of them
}