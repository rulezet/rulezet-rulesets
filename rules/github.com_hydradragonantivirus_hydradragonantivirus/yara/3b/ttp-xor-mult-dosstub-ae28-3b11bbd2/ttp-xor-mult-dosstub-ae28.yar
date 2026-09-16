rule TTP_XOR_MULT_DOSStub_ae28 {
  strings:
    $key_ae28 = { fa 40 [2] 8e 58 [2] c9 5a [2] 8e 4b [2] c0 47 [2] cc 4d [2] db 46 [2] c0 08 [2] fd }

  condition:
    any of them
}