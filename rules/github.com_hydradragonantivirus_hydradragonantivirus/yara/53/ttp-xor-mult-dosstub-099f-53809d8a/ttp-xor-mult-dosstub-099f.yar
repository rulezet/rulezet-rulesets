rule TTP_XOR_MULT_DOSStub_099f {
  strings:
    $key_099f = { 5d f7 [2] 29 ef [2] 6e ed [2] 29 fc [2] 67 f0 [2] 6b fa [2] 7c f1 [2] 67 bf [2] 5a }

  condition:
    any of them
}