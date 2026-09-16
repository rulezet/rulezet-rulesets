rule TTP_XOR_MULT_DOSStub_ae57 {
  strings:
    $key_ae57 = { fa 3f [2] 8e 27 [2] c9 25 [2] 8e 34 [2] c0 38 [2] cc 32 [2] db 39 [2] c0 77 [2] fd }

  condition:
    any of them
}