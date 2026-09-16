rule TTP_XOR_MULT_DOSStub_b8cf {
  strings:
    $key_b8cf = { ec a7 [2] 98 bf [2] df bd [2] 98 ac [2] d6 a0 [2] da aa [2] cd a1 [2] d6 ef [2] eb }

  condition:
    any of them
}