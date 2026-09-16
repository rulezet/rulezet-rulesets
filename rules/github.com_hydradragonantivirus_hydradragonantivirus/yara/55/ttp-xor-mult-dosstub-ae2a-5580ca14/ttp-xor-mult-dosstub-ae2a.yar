rule TTP_XOR_MULT_DOSStub_ae2a {
  strings:
    $key_ae2a = { fa 42 [2] 8e 5a [2] c9 58 [2] 8e 49 [2] c0 45 [2] cc 4f [2] db 44 [2] c0 0a [2] fd }

  condition:
    any of them
}