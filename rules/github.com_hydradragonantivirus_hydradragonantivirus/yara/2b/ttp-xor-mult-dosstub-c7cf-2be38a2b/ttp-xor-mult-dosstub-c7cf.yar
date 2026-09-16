rule TTP_XOR_MULT_DOSStub_c7cf {
  strings:
    $key_c7cf = { 93 a7 [2] e7 bf [2] a0 bd [2] e7 ac [2] a9 a0 [2] a5 aa [2] b2 a1 [2] a9 ef [2] 94 }

  condition:
    any of them
}