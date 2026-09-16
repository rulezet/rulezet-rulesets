rule TTP_XOR_MULT_DOSStub_b48a {
  strings:
    $key_b48a = { e0 e2 [2] 94 fa [2] d3 f8 [2] 94 e9 [2] da e5 [2] d6 ef [2] c1 e4 [2] da aa [2] e7 }

  condition:
    any of them
}