rule TTP_XOR_MULT_DOSStub_04cf {
  strings:
    $key_04cf = { 50 a7 [2] 24 bf [2] 63 bd [2] 24 ac [2] 6a a0 [2] 66 aa [2] 71 a1 [2] 6a ef [2] 57 }

  condition:
    any of them
}