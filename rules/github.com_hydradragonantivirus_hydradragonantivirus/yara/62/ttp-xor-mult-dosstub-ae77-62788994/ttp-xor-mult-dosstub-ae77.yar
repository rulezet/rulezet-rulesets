rule TTP_XOR_MULT_DOSStub_ae77 {
  strings:
    $key_ae77 = { fa 1f [2] 8e 07 [2] c9 05 [2] 8e 14 [2] c0 18 [2] cc 12 [2] db 19 [2] c0 57 [2] fd }

  condition:
    any of them
}