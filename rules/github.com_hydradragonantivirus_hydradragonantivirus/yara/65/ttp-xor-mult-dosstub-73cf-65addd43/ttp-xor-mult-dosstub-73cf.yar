rule TTP_XOR_MULT_DOSStub_73cf {
  strings:
    $key_73cf = { 27 a7 [2] 53 bf [2] 14 bd [2] 53 ac [2] 1d a0 [2] 11 aa [2] 06 a1 [2] 1d ef [2] 20 }

  condition:
    any of them
}