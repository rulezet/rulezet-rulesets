rule TTP_XOR_MULT_DOSStub_aee2 {
  strings:
    $key_aee2 = { fa 8a [2] 8e 92 [2] c9 90 [2] 8e 81 [2] c0 8d [2] cc 87 [2] db 8c [2] c0 c2 [2] fd }

  condition:
    any of them
}