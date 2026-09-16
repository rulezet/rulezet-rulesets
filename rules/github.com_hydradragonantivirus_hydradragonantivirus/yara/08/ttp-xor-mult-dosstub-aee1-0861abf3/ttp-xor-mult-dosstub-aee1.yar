rule TTP_XOR_MULT_DOSStub_aee1 {
  strings:
    $key_aee1 = { fa 89 [2] 8e 91 [2] c9 93 [2] 8e 82 [2] c0 8e [2] cc 84 [2] db 8f [2] c0 c1 [2] fd }

  condition:
    any of them
}