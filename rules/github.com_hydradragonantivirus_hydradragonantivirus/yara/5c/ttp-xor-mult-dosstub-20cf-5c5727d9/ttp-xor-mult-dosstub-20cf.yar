rule TTP_XOR_MULT_DOSStub_20cf {
  strings:
    $key_20cf = { 74 a7 [2] 00 bf [2] 47 bd [2] 00 ac [2] 4e a0 [2] 42 aa [2] 55 a1 [2] 4e ef [2] 73 }

  condition:
    any of them
}