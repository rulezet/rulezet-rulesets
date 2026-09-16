rule TTP_XOR_MULT_DOSStub_c8cf {
  strings:
    $key_c8cf = { 9c a7 [2] e8 bf [2] af bd [2] e8 ac [2] a6 a0 [2] aa aa [2] bd a1 [2] a6 ef [2] 9b }

  condition:
    any of them
}