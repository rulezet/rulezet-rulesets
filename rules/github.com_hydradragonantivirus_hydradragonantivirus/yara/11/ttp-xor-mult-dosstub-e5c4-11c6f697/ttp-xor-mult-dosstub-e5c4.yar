rule TTP_XOR_MULT_DOSStub_e5c4 {
  strings:
    $key_e5c4 = { b1 ac [2] c5 b4 [2] 82 b6 [2] c5 a7 [2] 8b ab [2] 87 a1 [2] 90 aa [2] 8b e4 [2] b6 }

  condition:
    any of them
}