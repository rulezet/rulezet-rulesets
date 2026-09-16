rule TTP_XOR_MULT_DOSStub_b997 {
  strings:
    $key_b997 = { ed ff [2] 99 e7 [2] de e5 [2] 99 f4 [2] d7 f8 [2] db f2 [2] cc f9 [2] d7 b7 [2] ea }

  condition:
    any of them
}