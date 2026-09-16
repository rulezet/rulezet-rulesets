rule TTP_XOR_MULT_DOSStub_d4cf {
  strings:
    $key_d4cf = { 80 a7 [2] f4 bf [2] b3 bd [2] f4 ac [2] ba a0 [2] b6 aa [2] a1 a1 [2] ba ef [2] 87 }

  condition:
    any of them
}