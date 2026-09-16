rule TTP_XOR_MULT_DOSStub_c0cf {
  strings:
    $key_c0cf = { 94 a7 [2] e0 bf [2] a7 bd [2] e0 ac [2] ae a0 [2] a2 aa [2] b5 a1 [2] ae ef [2] 93 }

  condition:
    any of them
}