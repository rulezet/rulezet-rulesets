rule TTP_XOR_MULT_DOSStub_74cf {
  strings:
    $key_74cf = { 20 a7 [2] 54 bf [2] 13 bd [2] 54 ac [2] 1a a0 [2] 16 aa [2] 01 a1 [2] 1a ef [2] 27 }

  condition:
    any of them
}