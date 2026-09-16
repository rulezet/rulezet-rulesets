rule TTP_XOR_MULT_DOSStub_aef6 {
  strings:
    $key_aef6 = { fa 9e [2] 8e 86 [2] c9 84 [2] 8e 95 [2] c0 99 [2] cc 93 [2] db 98 [2] c0 d6 [2] fd }

  condition:
    any of them
}