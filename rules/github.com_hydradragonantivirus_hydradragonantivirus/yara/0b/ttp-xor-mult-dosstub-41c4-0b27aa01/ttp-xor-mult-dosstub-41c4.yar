rule TTP_XOR_MULT_DOSStub_41c4 {
  strings:
    $key_41c4 = { 15 ac [2] 61 b4 [2] 26 b6 [2] 61 a7 [2] 2f ab [2] 23 a1 [2] 34 aa [2] 2f e4 [2] 12 }

  condition:
    any of them
}