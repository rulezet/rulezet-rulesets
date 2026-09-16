rule TTP_XOR_MULT_DOSStub_6c9f {
  strings:
    $key_6c9f = { 38 f7 [2] 4c ef [2] 0b ed [2] 4c fc [2] 02 f0 [2] 0e fa [2] 19 f1 [2] 02 bf [2] 3f }

  condition:
    any of them
}