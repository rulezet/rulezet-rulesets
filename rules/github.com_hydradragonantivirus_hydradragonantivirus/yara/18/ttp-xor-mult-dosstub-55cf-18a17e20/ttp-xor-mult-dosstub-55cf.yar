rule TTP_XOR_MULT_DOSStub_55cf {
  strings:
    $key_55cf = { 01 a7 [2] 75 bf [2] 32 bd [2] 75 ac [2] 3b a0 [2] 37 aa [2] 20 a1 [2] 3b ef [2] 06 }

  condition:
    any of them
}