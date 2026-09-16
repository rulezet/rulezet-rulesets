rule TTP_XOR_MULT_DOSStub_14cf {
  strings:
    $key_14cf = { 40 a7 [2] 34 bf [2] 73 bd [2] 34 ac [2] 7a a0 [2] 76 aa [2] 61 a1 [2] 7a ef [2] 47 }

  condition:
    any of them
}