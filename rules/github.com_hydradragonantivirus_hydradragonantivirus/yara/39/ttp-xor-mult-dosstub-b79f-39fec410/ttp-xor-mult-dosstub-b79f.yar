rule TTP_XOR_MULT_DOSStub_b79f {
  strings:
    $key_b79f = { e3 f7 [2] 97 ef [2] d0 ed [2] 97 fc [2] d9 f0 [2] d5 fa [2] c2 f1 [2] d9 bf [2] e4 }

  condition:
    any of them
}