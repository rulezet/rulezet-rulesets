rule TTP_XOR_MULT_DOSStub_e7cf {
  strings:
    $key_e7cf = { b3 a7 [2] c7 bf [2] 80 bd [2] c7 ac [2] 89 a0 [2] 85 aa [2] 92 a1 [2] 89 ef [2] b4 }

  condition:
    any of them
}