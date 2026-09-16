rule TTP_XOR_MULT_DOSStub_77cf {
  strings:
    $key_77cf = { 23 a7 [2] 57 bf [2] 10 bd [2] 57 ac [2] 19 a0 [2] 15 aa [2] 02 a1 [2] 19 ef [2] 24 }

  condition:
    any of them
}