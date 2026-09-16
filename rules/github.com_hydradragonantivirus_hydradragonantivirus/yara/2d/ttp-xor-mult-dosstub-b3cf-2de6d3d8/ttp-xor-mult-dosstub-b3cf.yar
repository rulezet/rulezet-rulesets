rule TTP_XOR_MULT_DOSStub_b3cf {
  strings:
    $key_b3cf = { e7 a7 [2] 93 bf [2] d4 bd [2] 93 ac [2] dd a0 [2] d1 aa [2] c6 a1 [2] dd ef [2] e0 }

  condition:
    any of them
}