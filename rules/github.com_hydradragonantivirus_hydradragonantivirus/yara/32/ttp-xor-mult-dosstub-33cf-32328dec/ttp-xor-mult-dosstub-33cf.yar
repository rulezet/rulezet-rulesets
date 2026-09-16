rule TTP_XOR_MULT_DOSStub_33cf {
  strings:
    $key_33cf = { 67 a7 [2] 13 bf [2] 54 bd [2] 13 ac [2] 5d a0 [2] 51 aa [2] 46 a1 [2] 5d ef [2] 60 }

  condition:
    any of them
}