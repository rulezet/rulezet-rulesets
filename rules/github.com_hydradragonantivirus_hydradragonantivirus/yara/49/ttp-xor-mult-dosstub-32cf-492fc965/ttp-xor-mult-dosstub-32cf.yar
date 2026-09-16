rule TTP_XOR_MULT_DOSStub_32cf {
  strings:
    $key_32cf = { 66 a7 [2] 12 bf [2] 55 bd [2] 12 ac [2] 5c a0 [2] 50 aa [2] 47 a1 [2] 5c ef [2] 61 }

  condition:
    any of them
}