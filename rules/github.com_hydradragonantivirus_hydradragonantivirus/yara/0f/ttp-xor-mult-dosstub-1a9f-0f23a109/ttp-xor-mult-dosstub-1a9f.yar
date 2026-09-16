rule TTP_XOR_MULT_DOSStub_1a9f {
  strings:
    $key_1a9f = { 4e f7 [2] 3a ef [2] 7d ed [2] 3a fc [2] 74 f0 [2] 78 fa [2] 6f f1 [2] 74 bf [2] 49 }

  condition:
    any of them
}