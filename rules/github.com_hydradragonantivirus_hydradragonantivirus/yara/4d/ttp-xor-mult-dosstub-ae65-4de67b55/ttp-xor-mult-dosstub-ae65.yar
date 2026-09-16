rule TTP_XOR_MULT_DOSStub_ae65 {
  strings:
    $key_ae65 = { fa 0d [2] 8e 15 [2] c9 17 [2] 8e 06 [2] c0 0a [2] cc 00 [2] db 0b [2] c0 45 [2] fd }

  condition:
    any of them
}