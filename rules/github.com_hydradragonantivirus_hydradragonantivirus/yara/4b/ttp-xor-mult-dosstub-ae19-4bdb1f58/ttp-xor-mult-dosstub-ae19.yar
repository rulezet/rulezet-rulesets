rule TTP_XOR_MULT_DOSStub_ae19 {
  strings:
    $key_ae19 = { fa 71 [2] 8e 69 [2] c9 6b [2] 8e 7a [2] c0 76 [2] cc 7c [2] db 77 [2] c0 39 [2] fd }

  condition:
    any of them
}