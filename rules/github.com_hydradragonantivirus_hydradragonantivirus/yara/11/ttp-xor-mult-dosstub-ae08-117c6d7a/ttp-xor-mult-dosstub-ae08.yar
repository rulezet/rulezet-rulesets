rule TTP_XOR_MULT_DOSStub_ae08 {
  strings:
    $key_ae08 = { fa 60 [2] 8e 78 [2] c9 7a [2] 8e 6b [2] c0 67 [2] cc 6d [2] db 66 [2] c0 28 [2] fd }

  condition:
    any of them
}