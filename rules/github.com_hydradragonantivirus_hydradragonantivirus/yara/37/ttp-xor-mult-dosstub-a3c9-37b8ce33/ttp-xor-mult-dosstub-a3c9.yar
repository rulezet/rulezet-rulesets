rule TTP_XOR_MULT_DOSStub_a3c9 {
  strings:
    $key_a3c9 = { f7 a1 [2] 83 b9 [2] c4 bb [2] 83 aa [2] cd a6 [2] c1 ac [2] d6 a7 [2] cd e9 [2] f0 }

  condition:
    any of them
}