rule TTP_XOR_MULT_DOSStub_b5cf {
  strings:
    $key_b5cf = { e1 a7 [2] 95 bf [2] d2 bd [2] 95 ac [2] db a0 [2] d7 aa [2] c0 a1 [2] db ef [2] e6 }

  condition:
    any of them
}