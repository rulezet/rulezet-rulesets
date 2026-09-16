rule TTP_XOR_MULT_DOSStub_e1cf {
  strings:
    $key_e1cf = { b5 a7 [2] c1 bf [2] 86 bd [2] c1 ac [2] 8f a0 [2] 83 aa [2] 94 a1 [2] 8f ef [2] b2 }

  condition:
    any of them
}