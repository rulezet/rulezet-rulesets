rule TTP_XOR_MULT_DOSStub_b49f {
  strings:
    $key_b49f = { e0 f7 [2] 94 ef [2] d3 ed [2] 94 fc [2] da f0 [2] d6 fa [2] c1 f1 [2] da bf [2] e7 }

  condition:
    any of them
}