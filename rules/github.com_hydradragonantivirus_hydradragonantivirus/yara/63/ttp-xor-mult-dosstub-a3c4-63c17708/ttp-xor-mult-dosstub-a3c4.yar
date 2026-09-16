rule TTP_XOR_MULT_DOSStub_a3c4 {
  strings:
    $key_a3c4 = { f7 ac [2] 83 b4 [2] c4 b6 [2] 83 a7 [2] cd ab [2] c1 a1 [2] d6 aa [2] cd e4 [2] f0 }

  condition:
    any of them
}