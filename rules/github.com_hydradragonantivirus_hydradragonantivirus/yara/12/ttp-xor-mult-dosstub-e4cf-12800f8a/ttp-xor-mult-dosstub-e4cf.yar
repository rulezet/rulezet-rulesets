rule TTP_XOR_MULT_DOSStub_e4cf {
  strings:
    $key_e4cf = { b0 a7 [2] c4 bf [2] 83 bd [2] c4 ac [2] 8a a0 [2] 86 aa [2] 91 a1 [2] 8a ef [2] b7 }

  condition:
    any of them
}