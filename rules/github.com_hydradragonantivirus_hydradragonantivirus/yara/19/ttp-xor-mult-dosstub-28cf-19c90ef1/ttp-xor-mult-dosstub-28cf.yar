rule TTP_XOR_MULT_DOSStub_28cf {
  strings:
    $key_28cf = { 7c a7 [2] 08 bf [2] 4f bd [2] 08 ac [2] 46 a0 [2] 4a aa [2] 5d a1 [2] 46 ef [2] 7b }

  condition:
    any of them
}