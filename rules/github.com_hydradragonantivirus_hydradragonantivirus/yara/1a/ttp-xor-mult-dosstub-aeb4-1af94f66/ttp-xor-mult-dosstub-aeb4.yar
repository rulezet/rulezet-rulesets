rule TTP_XOR_MULT_DOSStub_aeb4 {
  strings:
    $key_aeb4 = { fa dc [2] 8e c4 [2] c9 c6 [2] 8e d7 [2] c0 db [2] cc d1 [2] db da [2] c0 94 [2] fd }

  condition:
    any of them
}