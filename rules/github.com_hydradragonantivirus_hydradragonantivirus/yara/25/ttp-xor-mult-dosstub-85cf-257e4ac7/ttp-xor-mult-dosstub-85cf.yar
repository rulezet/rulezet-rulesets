rule TTP_XOR_MULT_DOSStub_85cf {
  strings:
    $key_85cf = { d1 a7 [2] a5 bf [2] e2 bd [2] a5 ac [2] eb a0 [2] e7 aa [2] f0 a1 [2] eb ef [2] d6 }

  condition:
    any of them
}