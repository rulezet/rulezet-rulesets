rule TTP_XOR_MULT_DOSStub_d8cf {
  strings:
    $key_d8cf = { 8c a7 [2] f8 bf [2] bf bd [2] f8 ac [2] b6 a0 [2] ba aa [2] ad a1 [2] b6 ef [2] 8b }

  condition:
    any of them
}