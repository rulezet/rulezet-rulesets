rule TTP_XOR_MULT_DOSStub_ae3f {
  strings:
    $key_ae3f = { fa 57 [2] 8e 4f [2] c9 4d [2] 8e 5c [2] c0 50 [2] cc 5a [2] db 51 [2] c0 1f [2] fd }

  condition:
    any of them
}