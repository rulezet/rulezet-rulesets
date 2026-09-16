rule TTP_XOR_MULT_DOSStub_ae64 {
  strings:
    $key_ae64 = { fa 0c [2] 8e 14 [2] c9 16 [2] 8e 07 [2] c0 0b [2] cc 01 [2] db 0a [2] c0 44 [2] fd }

  condition:
    any of them
}