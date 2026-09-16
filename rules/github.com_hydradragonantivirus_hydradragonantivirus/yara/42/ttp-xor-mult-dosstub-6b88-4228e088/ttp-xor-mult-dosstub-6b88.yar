rule TTP_XOR_MULT_DOSStub_6b88 {
  strings:
    $key_6b88 = { 3f e0 [2] 4b f8 [2] 0c fa [2] 4b eb [2] 05 e7 [2] 09 ed [2] 1e e6 [2] 05 a8 [2] 38 }

  condition:
    any of them
}