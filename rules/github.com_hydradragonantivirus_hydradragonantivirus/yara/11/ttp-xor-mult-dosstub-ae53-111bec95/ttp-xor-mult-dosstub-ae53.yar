rule TTP_XOR_MULT_DOSStub_ae53 {
  strings:
    $key_ae53 = { fa 3b [2] 8e 23 [2] c9 21 [2] 8e 30 [2] c0 3c [2] cc 36 [2] db 3d [2] c0 73 [2] fd }

  condition:
    any of them
}