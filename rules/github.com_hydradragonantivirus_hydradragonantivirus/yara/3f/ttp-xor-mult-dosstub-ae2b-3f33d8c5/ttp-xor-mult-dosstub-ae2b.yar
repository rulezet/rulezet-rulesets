rule TTP_XOR_MULT_DOSStub_ae2b {
  strings:
    $key_ae2b = { fa 43 [2] 8e 5b [2] c9 59 [2] 8e 48 [2] c0 44 [2] cc 4e [2] db 45 [2] c0 0b [2] fd }

  condition:
    any of them
}