rule TTP_XOR_MULT_DOSStub_0c9f {
  strings:
    $key_0c9f = { 58 f7 [2] 2c ef [2] 6b ed [2] 2c fc [2] 62 f0 [2] 6e fa [2] 79 f1 [2] 62 bf [2] 5f }

  condition:
    any of them
}