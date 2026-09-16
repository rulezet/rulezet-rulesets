rule TTP_XOR_MULT_DOSStub_b0cf {
  strings:
    $key_b0cf = { e4 a7 [2] 90 bf [2] d7 bd [2] 90 ac [2] de a0 [2] d2 aa [2] c5 a1 [2] de ef [2] e3 }

  condition:
    any of them
}