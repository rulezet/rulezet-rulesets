rule TTP_XOR_MULT_DOSStub_c1cf {
  strings:
    $key_c1cf = { 95 a7 [2] e1 bf [2] a6 bd [2] e1 ac [2] af a0 [2] a3 aa [2] b4 a1 [2] af ef [2] 92 }

  condition:
    any of them
}