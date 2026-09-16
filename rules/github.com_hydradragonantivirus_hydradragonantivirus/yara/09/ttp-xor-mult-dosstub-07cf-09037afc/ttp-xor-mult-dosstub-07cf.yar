rule TTP_XOR_MULT_DOSStub_07cf {
  strings:
    $key_07cf = { 53 a7 [2] 27 bf [2] 60 bd [2] 27 ac [2] 69 a0 [2] 65 aa [2] 72 a1 [2] 69 ef [2] 54 }

  condition:
    any of them
}