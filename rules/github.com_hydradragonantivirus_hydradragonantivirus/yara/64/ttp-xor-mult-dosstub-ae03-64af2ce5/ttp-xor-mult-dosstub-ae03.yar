rule TTP_XOR_MULT_DOSStub_ae03 {
  strings:
    $key_ae03 = { fa 6b [2] 8e 73 [2] c9 71 [2] 8e 60 [2] c0 6c [2] cc 66 [2] db 6d [2] c0 23 [2] fd }

  condition:
    any of them
}