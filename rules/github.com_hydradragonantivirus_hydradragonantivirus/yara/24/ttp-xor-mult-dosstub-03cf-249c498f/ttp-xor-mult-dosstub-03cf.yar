rule TTP_XOR_MULT_DOSStub_03cf {
  strings:
    $key_03cf = { 57 a7 [2] 23 bf [2] 64 bd [2] 23 ac [2] 6d a0 [2] 61 aa [2] 76 a1 [2] 6d ef [2] 50 }

  condition:
    any of them
}