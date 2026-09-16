rule TTP_XOR_MULT_DOSStub_67cf {
  strings:
    $key_67cf = { 33 a7 [2] 47 bf [2] 00 bd [2] 47 ac [2] 09 a0 [2] 05 aa [2] 12 a1 [2] 09 ef [2] 34 }

  condition:
    any of them
}