rule TTP_XOR_MULT_DOSStub_a7cf {
  strings:
    $key_a7cf = { f3 a7 [2] 87 bf [2] c0 bd [2] 87 ac [2] c9 a0 [2] c5 aa [2] d2 a1 [2] c9 ef [2] f4 }

  condition:
    any of them
}