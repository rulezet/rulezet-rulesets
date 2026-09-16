rule TTP_XOR_MULT_DOSStub_70cf {
  strings:
    $key_70cf = { 24 a7 [2] 50 bf [2] 17 bd [2] 50 ac [2] 1e a0 [2] 12 aa [2] 05 a1 [2] 1e ef [2] 23 }

  condition:
    any of them
}