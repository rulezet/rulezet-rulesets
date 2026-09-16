rule TTP_XOR_MULT_DOSStub_27cf {
  strings:
    $key_27cf = { 73 a7 [2] 07 bf [2] 40 bd [2] 07 ac [2] 49 a0 [2] 45 aa [2] 52 a1 [2] 49 ef [2] 74 }

  condition:
    any of them
}