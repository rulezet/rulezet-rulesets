rule TTP_XOR_MULT_DOSStub_789f {
  strings:
    $key_789f = { 2c f7 [2] 58 ef [2] 1f ed [2] 58 fc [2] 16 f0 [2] 1a fa [2] 0d f1 [2] 16 bf [2] 2b }

  condition:
    any of them
}