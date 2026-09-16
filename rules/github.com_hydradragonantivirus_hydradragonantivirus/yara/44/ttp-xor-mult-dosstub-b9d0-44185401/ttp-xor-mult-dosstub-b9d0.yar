rule TTP_XOR_MULT_DOSStub_b9d0 {
  strings:
    $key_b9d0 = { ed b8 [2] 99 a0 [2] de a2 [2] 99 b3 [2] d7 bf [2] db b5 [2] cc be [2] d7 f0 [2] ea }

  condition:
    any of them
}