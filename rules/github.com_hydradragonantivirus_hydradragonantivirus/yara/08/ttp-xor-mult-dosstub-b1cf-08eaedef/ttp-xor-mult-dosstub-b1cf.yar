rule TTP_XOR_MULT_DOSStub_b1cf {
  strings:
    $key_b1cf = { e5 a7 [2] 91 bf [2] d6 bd [2] 91 ac [2] df a0 [2] d3 aa [2] c4 a1 [2] df ef [2] e2 }

  condition:
    any of them
}