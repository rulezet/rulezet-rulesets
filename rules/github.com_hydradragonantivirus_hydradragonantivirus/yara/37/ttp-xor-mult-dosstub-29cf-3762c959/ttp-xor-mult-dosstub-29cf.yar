rule TTP_XOR_MULT_DOSStub_29cf {
  strings:
    $key_29cf = { 7d a7 [2] 09 bf [2] 4e bd [2] 09 ac [2] 47 a0 [2] 4b aa [2] 5c a1 [2] 47 ef [2] 7a }

  condition:
    any of them
}