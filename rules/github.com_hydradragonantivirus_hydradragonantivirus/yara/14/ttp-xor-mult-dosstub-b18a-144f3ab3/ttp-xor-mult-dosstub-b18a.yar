rule TTP_XOR_MULT_DOSStub_b18a {
  strings:
    $key_b18a = { e5 e2 [2] 91 fa [2] d6 f8 [2] 91 e9 [2] df e5 [2] d3 ef [2] c4 e4 [2] df aa [2] e2 }

  condition:
    any of them
}