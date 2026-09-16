rule TTP_XOR_MULT_DOSStub_ae09 {
  strings:
    $key_ae09 = { fa 61 [2] 8e 79 [2] c9 7b [2] 8e 6a [2] c0 66 [2] cc 6c [2] db 67 [2] c0 29 [2] fd }

  condition:
    any of them
}