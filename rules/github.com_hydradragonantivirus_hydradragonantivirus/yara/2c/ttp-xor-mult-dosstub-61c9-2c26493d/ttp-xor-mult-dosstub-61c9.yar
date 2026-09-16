rule TTP_XOR_MULT_DOSStub_61c9 {
  strings:
    $key_61c9 = { 35 a1 [2] 41 b9 [2] 06 bb [2] 41 aa [2] 0f a6 [2] 03 ac [2] 14 a7 [2] 0f e9 [2] 32 }

  condition:
    any of them
}