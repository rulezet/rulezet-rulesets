rule TTP_XOR_MULT_DOSStub_3a9f {
  strings:
    $key_3a9f = { 6e f7 [2] 1a ef [2] 5d ed [2] 1a fc [2] 54 f0 [2] 58 fa [2] 4f f1 [2] 54 bf [2] 69 }

  condition:
    any of them
}