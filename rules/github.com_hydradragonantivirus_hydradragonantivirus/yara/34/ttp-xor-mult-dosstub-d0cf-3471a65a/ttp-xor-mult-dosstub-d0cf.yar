rule TTP_XOR_MULT_DOSStub_d0cf {
  strings:
    $key_d0cf = { 84 a7 [2] f0 bf [2] b7 bd [2] f0 ac [2] be a0 [2] b2 aa [2] a5 a1 [2] be ef [2] 83 }

  condition:
    any of them
}