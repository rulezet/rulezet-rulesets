rule TTP_XOR_MULT_DOSStub_b59f {
  strings:
    $key_b59f = { e1 f7 [2] 95 ef [2] d2 ed [2] 95 fc [2] db f0 [2] d7 fa [2] c0 f1 [2] db bf [2] e6 }

  condition:
    any of them
}