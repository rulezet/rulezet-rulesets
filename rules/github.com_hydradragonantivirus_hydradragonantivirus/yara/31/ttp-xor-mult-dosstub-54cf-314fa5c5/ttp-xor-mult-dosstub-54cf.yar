rule TTP_XOR_MULT_DOSStub_54cf {
  strings:
    $key_54cf = { 00 a7 [2] 74 bf [2] 33 bd [2] 74 ac [2] 3a a0 [2] 36 aa [2] 21 a1 [2] 3a ef [2] 07 }

  condition:
    any of them
}