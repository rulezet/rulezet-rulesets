rule TTP_XOR_MULT_DOSStub_4c9f {
  strings:
    $key_4c9f = { 18 f7 [2] 6c ef [2] 2b ed [2] 6c fc [2] 22 f0 [2] 2e fa [2] 39 f1 [2] 22 bf [2] 1f }

  condition:
    any of them
}