rule TTP_XOR_MULT_DOSStub_59cf {
  strings:
    $key_59cf = { 0d a7 [2] 79 bf [2] 3e bd [2] 79 ac [2] 37 a0 [2] 3b aa [2] 2c a1 [2] 37 ef [2] 0a }

  condition:
    any of them
}