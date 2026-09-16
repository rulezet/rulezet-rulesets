rule TTP_XOR_MULT_DOSStub_75cf {
  strings:
    $key_75cf = { 21 a7 [2] 55 bf [2] 12 bd [2] 55 ac [2] 1b a0 [2] 17 aa [2] 00 a1 [2] 1b ef [2] 26 }

  condition:
    any of them
}