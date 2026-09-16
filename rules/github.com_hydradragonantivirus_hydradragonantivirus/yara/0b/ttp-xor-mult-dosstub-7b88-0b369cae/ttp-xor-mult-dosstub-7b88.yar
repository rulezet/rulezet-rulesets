rule TTP_XOR_MULT_DOSStub_7b88 {
  strings:
    $key_7b88 = { 2f e0 [2] 5b f8 [2] 1c fa [2] 5b eb [2] 15 e7 [2] 19 ed [2] 0e e6 [2] 15 a8 [2] 28 }

  condition:
    any of them
}