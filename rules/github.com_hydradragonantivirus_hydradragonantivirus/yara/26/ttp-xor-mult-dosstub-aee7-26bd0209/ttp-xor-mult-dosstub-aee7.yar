rule TTP_XOR_MULT_DOSStub_aee7 {
  strings:
    $key_aee7 = { fa 8f [2] 8e 97 [2] c9 95 [2] 8e 84 [2] c0 88 [2] cc 82 [2] db 89 [2] c0 c7 [2] fd }

  condition:
    any of them
}