rule TTP_XOR_MULT_DOSStub_ae51 {
  strings:
    $key_ae51 = { fa 39 [2] 8e 21 [2] c9 23 [2] 8e 32 [2] c0 3e [2] cc 34 [2] db 3f [2] c0 71 [2] fd }

  condition:
    any of them
}