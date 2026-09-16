rule TTP_XOR_MULT_DOSStub_ae17 {
  strings:
    $key_ae17 = { fa 7f [2] 8e 67 [2] c9 65 [2] 8e 74 [2] c0 78 [2] cc 72 [2] db 79 [2] c0 37 [2] fd }

  condition:
    any of them
}