rule TTP_XOR_MULT_DOSStub_e6cf {
  strings:
    $key_e6cf = { b2 a7 [2] c6 bf [2] 81 bd [2] c6 ac [2] 88 a0 [2] 84 aa [2] 93 a1 [2] 88 ef [2] b5 }

  condition:
    any of them
}