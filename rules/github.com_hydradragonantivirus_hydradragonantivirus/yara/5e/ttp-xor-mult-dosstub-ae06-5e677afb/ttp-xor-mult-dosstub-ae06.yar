rule TTP_XOR_MULT_DOSStub_ae06 {
  strings:
    $key_ae06 = { fa 6e [2] 8e 76 [2] c9 74 [2] 8e 65 [2] c0 69 [2] cc 63 [2] db 68 [2] c0 26 [2] fd }

  condition:
    any of them
}