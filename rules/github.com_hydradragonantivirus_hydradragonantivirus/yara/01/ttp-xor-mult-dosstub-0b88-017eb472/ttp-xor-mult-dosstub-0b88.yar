rule TTP_XOR_MULT_DOSStub_0b88 {
  strings:
    $key_0b88 = { 5f e0 [2] 2b f8 [2] 6c fa [2] 2b eb [2] 65 e7 [2] 69 ed [2] 7e e6 [2] 65 a8 [2] 58 }

  condition:
    any of them
}