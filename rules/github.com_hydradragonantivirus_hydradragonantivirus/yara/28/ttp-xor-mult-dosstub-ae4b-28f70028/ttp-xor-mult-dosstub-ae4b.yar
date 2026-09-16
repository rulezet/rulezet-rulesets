rule TTP_XOR_MULT_DOSStub_ae4b {
  strings:
    $key_ae4b = { fa 23 [2] 8e 3b [2] c9 39 [2] 8e 28 [2] c0 24 [2] cc 2e [2] db 25 [2] c0 6b [2] fd }

  condition:
    any of them
}