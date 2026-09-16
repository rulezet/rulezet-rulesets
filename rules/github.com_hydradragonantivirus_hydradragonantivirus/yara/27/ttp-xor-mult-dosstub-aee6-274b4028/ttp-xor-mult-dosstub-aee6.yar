rule TTP_XOR_MULT_DOSStub_aee6 {
  strings:
    $key_aee6 = { fa 8e [2] 8e 96 [2] c9 94 [2] 8e 85 [2] c0 89 [2] cc 83 [2] db 88 [2] c0 c6 [2] fd }

  condition:
    any of them
}