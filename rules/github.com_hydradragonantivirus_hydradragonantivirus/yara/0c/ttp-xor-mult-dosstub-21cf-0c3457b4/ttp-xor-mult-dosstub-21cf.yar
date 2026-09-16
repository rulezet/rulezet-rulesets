rule TTP_XOR_MULT_DOSStub_21cf {
  strings:
    $key_21cf = { 75 a7 [2] 01 bf [2] 46 bd [2] 01 ac [2] 4f a0 [2] 43 aa [2] 54 a1 [2] 4f ef [2] 72 }

  condition:
    any of them
}