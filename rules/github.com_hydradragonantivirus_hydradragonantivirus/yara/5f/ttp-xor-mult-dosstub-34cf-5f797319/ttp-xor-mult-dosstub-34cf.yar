rule TTP_XOR_MULT_DOSStub_34cf {
  strings:
    $key_34cf = { 60 a7 [2] 14 bf [2] 53 bd [2] 14 ac [2] 5a a0 [2] 56 aa [2] 41 a1 [2] 5a ef [2] 67 }

  condition:
    any of them
}