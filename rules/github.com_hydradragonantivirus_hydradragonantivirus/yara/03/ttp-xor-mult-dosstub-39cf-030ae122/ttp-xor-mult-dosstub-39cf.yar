rule TTP_XOR_MULT_DOSStub_39cf {
  strings:
    $key_39cf = { 6d a7 [2] 19 bf [2] 5e bd [2] 19 ac [2] 57 a0 [2] 5b aa [2] 4c a1 [2] 57 ef [2] 6a }

  condition:
    any of them
}