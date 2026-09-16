rule TTP_XOR_MULT_DOSStub_ae68 {
  strings:
    $key_ae68 = { fa 00 [2] 8e 18 [2] c9 1a [2] 8e 0b [2] c0 07 [2] cc 0d [2] db 06 [2] c0 48 [2] fd }

  condition:
    any of them
}