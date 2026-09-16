rule TTP_XOR_MULT_DOSStub_ae3b {
  strings:
    $key_ae3b = { fa 53 [2] 8e 4b [2] c9 49 [2] 8e 58 [2] c0 54 [2] cc 5e [2] db 55 [2] c0 1b [2] fd }

  condition:
    any of them
}