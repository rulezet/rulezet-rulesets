rule TTP_XOR_MULT_DOSStub_aefd {
  strings:
    $key_aefd = { fa 95 [2] 8e 8d [2] c9 8f [2] 8e 9e [2] c0 92 [2] cc 98 [2] db 93 [2] c0 dd [2] fd }

  condition:
    any of them
}