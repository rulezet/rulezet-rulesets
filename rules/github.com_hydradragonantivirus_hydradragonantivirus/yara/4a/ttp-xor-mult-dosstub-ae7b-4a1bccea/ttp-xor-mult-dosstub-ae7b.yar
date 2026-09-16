rule TTP_XOR_MULT_DOSStub_ae7b {
  strings:
    $key_ae7b = { fa 13 [2] 8e 0b [2] c9 09 [2] 8e 18 [2] c0 14 [2] cc 1e [2] db 15 [2] c0 5b [2] fd }

  condition:
    any of them
}