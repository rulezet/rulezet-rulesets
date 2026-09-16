rule TTP_XOR_MULT_DOSStub_44cf {
  strings:
    $key_44cf = { 10 a7 [2] 64 bf [2] 23 bd [2] 64 ac [2] 2a a0 [2] 26 aa [2] 31 a1 [2] 2a ef [2] 17 }

  condition:
    any of them
}