rule TTP_XOR_MULT_DOSStub_61cf {
  strings:
    $key_61cf = { 35 a7 [2] 41 bf [2] 06 bd [2] 41 ac [2] 0f a0 [2] 03 aa [2] 14 a1 [2] 0f ef [2] 32 }

  condition:
    any of them
}