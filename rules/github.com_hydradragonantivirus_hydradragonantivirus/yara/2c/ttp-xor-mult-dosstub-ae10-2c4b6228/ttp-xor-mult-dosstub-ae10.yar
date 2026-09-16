rule TTP_XOR_MULT_DOSStub_ae10 {
  strings:
    $key_ae10 = { fa 78 [2] 8e 60 [2] c9 62 [2] 8e 73 [2] c0 7f [2] cc 75 [2] db 7e [2] c0 30 [2] fd }

  condition:
    any of them
}