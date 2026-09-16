rule TTP_XOR_MULT_DOSStub_bc8a {
  strings:
    $key_bc8a = { e8 e2 [2] 9c fa [2] db f8 [2] 9c e9 [2] d2 e5 [2] de ef [2] c9 e4 [2] d2 aa [2] ef }

  condition:
    any of them
}