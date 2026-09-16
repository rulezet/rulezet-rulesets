rule TTP_XOR_MULT_DOSStub_ae80 {
  strings:
    $key_ae80 = { fa e8 [2] 8e f0 [2] c9 f2 [2] 8e e3 [2] c0 ef [2] cc e5 [2] db ee [2] c0 a0 [2] fd }

  condition:
    any of them
}