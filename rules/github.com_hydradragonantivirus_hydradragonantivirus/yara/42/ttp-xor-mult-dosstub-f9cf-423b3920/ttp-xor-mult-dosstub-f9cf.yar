rule TTP_XOR_MULT_DOSStub_f9cf {
  strings:
    $key_f9cf = { ad a7 [2] d9 bf [2] 9e bd [2] d9 ac [2] 97 a0 [2] 9b aa [2] 8c a1 [2] 97 ef [2] aa }

  condition:
    any of them
}