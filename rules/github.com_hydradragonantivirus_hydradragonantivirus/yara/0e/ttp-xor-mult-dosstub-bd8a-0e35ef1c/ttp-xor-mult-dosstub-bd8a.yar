rule TTP_XOR_MULT_DOSStub_bd8a {
  strings:
    $key_bd8a = { e9 e2 [2] 9d fa [2] da f8 [2] 9d e9 [2] d3 e5 [2] df ef [2] c8 e4 [2] d3 aa [2] ee }

  condition:
    any of them
}