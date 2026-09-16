rule TTP_XOR_MULT_DOSStub_b986 {
  strings:
    $key_b986 = { ed ee [2] 99 f6 [2] de f4 [2] 99 e5 [2] d7 e9 [2] db e3 [2] cc e8 [2] d7 a6 [2] ea }

  condition:
    any of them
}