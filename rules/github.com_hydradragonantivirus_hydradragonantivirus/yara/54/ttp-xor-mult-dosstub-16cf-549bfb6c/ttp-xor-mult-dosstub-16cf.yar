rule TTP_XOR_MULT_DOSStub_16cf {
  strings:
    $key_16cf = { 42 a7 [2] 36 bf [2] 71 bd [2] 36 ac [2] 78 a0 [2] 74 aa [2] 63 a1 [2] 78 ef [2] 45 }

  condition:
    any of them
}