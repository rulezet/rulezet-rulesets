rule TTP_XOR_MULT_DOSStub_52cf {
  strings:
    $key_52cf = { 06 a7 [2] 72 bf [2] 35 bd [2] 72 ac [2] 3c a0 [2] 30 aa [2] 27 a1 [2] 3c ef [2] 01 }

  condition:
    any of them
}