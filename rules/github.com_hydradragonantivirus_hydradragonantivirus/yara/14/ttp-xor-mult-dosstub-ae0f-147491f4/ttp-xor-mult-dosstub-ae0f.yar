rule TTP_XOR_MULT_DOSStub_ae0f {
  strings:
    $key_ae0f = { fa 67 [2] 8e 7f [2] c9 7d [2] 8e 6c [2] c0 60 [2] cc 6a [2] db 61 [2] c0 2f [2] fd }

  condition:
    any of them
}