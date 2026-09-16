rule TTP_XOR_MULT_DOSStub_b2cf {
  strings:
    $key_b2cf = { e6 a7 [2] 92 bf [2] d5 bd [2] 92 ac [2] dc a0 [2] d0 aa [2] c7 a1 [2] dc ef [2] e1 }

  condition:
    any of them
}