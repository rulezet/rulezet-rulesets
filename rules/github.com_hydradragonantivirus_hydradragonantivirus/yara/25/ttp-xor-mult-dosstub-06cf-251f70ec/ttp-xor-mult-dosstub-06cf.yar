rule TTP_XOR_MULT_DOSStub_06cf {
  strings:
    $key_06cf = { 52 a7 [2] 26 bf [2] 61 bd [2] 26 ac [2] 68 a0 [2] 64 aa [2] 73 a1 [2] 68 ef [2] 55 }

  condition:
    any of them
}