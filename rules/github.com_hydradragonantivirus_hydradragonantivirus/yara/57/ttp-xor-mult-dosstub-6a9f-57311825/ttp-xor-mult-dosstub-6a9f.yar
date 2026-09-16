rule TTP_XOR_MULT_DOSStub_6a9f {
  strings:
    $key_6a9f = { 3e f7 [2] 4a ef [2] 0d ed [2] 4a fc [2] 04 f0 [2] 08 fa [2] 1f f1 [2] 04 bf [2] 39 }

  condition:
    any of them
}