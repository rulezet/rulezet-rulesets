rule TTP_XOR_MULT_DOSStub_26cf {
  strings:
    $key_26cf = { 72 a7 [2] 06 bf [2] 41 bd [2] 06 ac [2] 48 a0 [2] 44 aa [2] 53 a1 [2] 48 ef [2] 75 }

  condition:
    any of them
}