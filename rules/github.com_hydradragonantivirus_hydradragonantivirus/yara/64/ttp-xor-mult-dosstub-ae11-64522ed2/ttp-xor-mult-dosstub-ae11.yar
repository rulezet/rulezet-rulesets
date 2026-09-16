rule TTP_XOR_MULT_DOSStub_ae11 {
  strings:
    $key_ae11 = { fa 79 [2] 8e 61 [2] c9 63 [2] 8e 72 [2] c0 7e [2] cc 74 [2] db 7f [2] c0 31 [2] fd }

  condition:
    any of them
}