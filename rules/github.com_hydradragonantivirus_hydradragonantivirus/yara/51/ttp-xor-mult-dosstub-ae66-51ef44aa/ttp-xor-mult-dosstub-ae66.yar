rule TTP_XOR_MULT_DOSStub_ae66 {
  strings:
    $key_ae66 = { fa 0e [2] 8e 16 [2] c9 14 [2] 8e 05 [2] c0 09 [2] cc 03 [2] db 08 [2] c0 46 [2] fd }

  condition:
    any of them
}