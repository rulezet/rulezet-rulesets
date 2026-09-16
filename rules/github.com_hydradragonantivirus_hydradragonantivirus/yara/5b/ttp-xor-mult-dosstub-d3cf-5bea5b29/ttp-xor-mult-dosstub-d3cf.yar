rule TTP_XOR_MULT_DOSStub_d3cf {
  strings:
    $key_d3cf = { 87 a7 [2] f3 bf [2] b4 bd [2] f3 ac [2] bd a0 [2] b1 aa [2] a6 a1 [2] bd ef [2] 80 }

  condition:
    any of them
}