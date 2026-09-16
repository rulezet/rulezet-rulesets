rule TTP_XOR_MULT_DOSStub_e3cf {
  strings:
    $key_e3cf = { b7 a7 [2] c3 bf [2] 84 bd [2] c3 ac [2] 8d a0 [2] 81 aa [2] 96 a1 [2] 8d ef [2] b0 }

  condition:
    any of them
}