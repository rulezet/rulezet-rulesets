rule TTP_XOR_MULT_DOSStub_09cf {
  strings:
    $key_09cf = { 5d a7 [2] 29 bf [2] 6e bd [2] 29 ac [2] 67 a0 [2] 6b aa [2] 7c a1 [2] 67 ef [2] 5a }

  condition:
    any of them
}