rule TTP_XOR_MULT_DOSStub_3c9f {
  strings:
    $key_3c9f = { 68 f7 [2] 1c ef [2] 5b ed [2] 1c fc [2] 52 f0 [2] 5e fa [2] 49 f1 [2] 52 bf [2] 6f }

  condition:
    any of them
}