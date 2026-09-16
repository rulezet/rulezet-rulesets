rule TTP_XOR_MULT_DOSStub_41cf {
  strings:
    $key_41cf = { 15 a7 [2] 61 bf [2] 26 bd [2] 61 ac [2] 2f a0 [2] 23 aa [2] 34 a1 [2] 2f ef [2] 12 }

  condition:
    any of them
}