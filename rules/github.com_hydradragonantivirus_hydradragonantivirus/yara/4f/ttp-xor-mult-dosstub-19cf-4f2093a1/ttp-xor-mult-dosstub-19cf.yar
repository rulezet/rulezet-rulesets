rule TTP_XOR_MULT_DOSStub_19cf {
  strings:
    $key_19cf = { 4d a7 [2] 39 bf [2] 7e bd [2] 39 ac [2] 77 a0 [2] 7b aa [2] 6c a1 [2] 77 ef [2] 4a }

  condition:
    any of them
}