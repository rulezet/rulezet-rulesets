rule TTP_XOR_MULT_DOSStub_ae35 {
  strings:
    $key_ae35 = { fa 5d [2] 8e 45 [2] c9 47 [2] 8e 56 [2] c0 5a [2] cc 50 [2] db 5b [2] c0 15 [2] fd }

  condition:
    any of them
}