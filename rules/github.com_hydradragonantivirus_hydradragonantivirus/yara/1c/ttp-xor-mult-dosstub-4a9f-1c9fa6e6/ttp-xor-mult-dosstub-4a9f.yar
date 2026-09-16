rule TTP_XOR_MULT_DOSStub_4a9f {
  strings:
    $key_4a9f = { 1e f7 [2] 6a ef [2] 2d ed [2] 6a fc [2] 24 f0 [2] 28 fa [2] 3f f1 [2] 24 bf [2] 19 }

  condition:
    any of them
}