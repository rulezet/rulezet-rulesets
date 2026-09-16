rule TTP_XOR_MULT_DOSStub_45cf {
  strings:
    $key_45cf = { 11 a7 [2] 65 bf [2] 22 bd [2] 65 ac [2] 2b a0 [2] 27 aa [2] 30 a1 [2] 2b ef [2] 16 }

  condition:
    any of them
}