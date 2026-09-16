rule TTP_XOR_MULT_DOSStub_ae05 {
  strings:
    $key_ae05 = { fa 6d [2] 8e 75 [2] c9 77 [2] 8e 66 [2] c0 6a [2] cc 60 [2] db 6b [2] c0 25 [2] fd }

  condition:
    any of them
}