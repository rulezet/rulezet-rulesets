rule TTP_XOR_MULT_DOSStub_689f {
  strings:
    $key_689f = { 3c f7 [2] 48 ef [2] 0f ed [2] 48 fc [2] 06 f0 [2] 0a fa [2] 1d f1 [2] 06 bf [2] 3b }

  condition:
    any of them
}