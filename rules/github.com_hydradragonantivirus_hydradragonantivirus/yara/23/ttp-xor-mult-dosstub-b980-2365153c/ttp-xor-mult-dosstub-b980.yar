rule TTP_XOR_MULT_DOSStub_b980 {
  strings:
    $key_b980 = { ed e8 [2] 99 f0 [2] de f2 [2] 99 e3 [2] d7 ef [2] db e5 [2] cc ee [2] d7 a0 [2] ea }

  condition:
    any of them
}