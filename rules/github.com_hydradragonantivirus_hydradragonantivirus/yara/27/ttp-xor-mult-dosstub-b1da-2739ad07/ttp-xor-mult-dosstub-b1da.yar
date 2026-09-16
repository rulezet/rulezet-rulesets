rule TTP_XOR_MULT_DOSStub_b1da {
  strings:
    $key_b1da = { e5 b2 [2] 91 aa [2] d6 a8 [2] 91 b9 [2] df b5 [2] d3 bf [2] c4 b4 [2] df fa [2] e2 }

  condition:
    any of them
}