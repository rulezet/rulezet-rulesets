rule TTP_XOR_MULT_DOSStub_b9d6 {
  strings:
    $key_b9d6 = { ed be [2] 99 a6 [2] de a4 [2] 99 b5 [2] d7 b9 [2] db b3 [2] cc b8 [2] d7 f6 [2] ea }

  condition:
    any of them
}