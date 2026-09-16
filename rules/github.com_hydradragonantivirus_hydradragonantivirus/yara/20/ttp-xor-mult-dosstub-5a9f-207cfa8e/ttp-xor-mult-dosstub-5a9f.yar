rule TTP_XOR_MULT_DOSStub_5a9f {
  strings:
    $key_5a9f = { 0e f7 [2] 7a ef [2] 3d ed [2] 7a fc [2] 34 f0 [2] 38 fa [2] 2f f1 [2] 34 bf [2] 09 }

  condition:
    any of them
}