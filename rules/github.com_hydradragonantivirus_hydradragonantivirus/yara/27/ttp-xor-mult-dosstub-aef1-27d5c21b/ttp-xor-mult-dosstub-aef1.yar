rule TTP_XOR_MULT_DOSStub_aef1 {
  strings:
    $key_aef1 = { fa 99 [2] 8e 81 [2] c9 83 [2] 8e 92 [2] c0 9e [2] cc 94 [2] db 9f [2] c0 d1 [2] fd }

  condition:
    any of them
}