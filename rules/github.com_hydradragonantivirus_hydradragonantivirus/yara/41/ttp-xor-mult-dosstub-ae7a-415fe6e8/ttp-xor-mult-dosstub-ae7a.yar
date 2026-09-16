rule TTP_XOR_MULT_DOSStub_ae7a {
  strings:
    $key_ae7a = { fa 12 [2] 8e 0a [2] c9 08 [2] 8e 19 [2] c0 15 [2] cc 1f [2] db 14 [2] c0 5a [2] fd }

  condition:
    any of them
}