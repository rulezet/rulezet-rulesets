rule TTP_XOR_MULT_DOSStub_2c9f {
  strings:
    $key_2c9f = { 78 f7 [2] 0c ef [2] 4b ed [2] 0c fc [2] 42 f0 [2] 4e fa [2] 59 f1 [2] 42 bf [2] 7f }

  condition:
    any of them
}