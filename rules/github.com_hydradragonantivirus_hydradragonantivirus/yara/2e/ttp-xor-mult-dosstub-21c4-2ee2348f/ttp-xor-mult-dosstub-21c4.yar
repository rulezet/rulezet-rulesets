rule TTP_XOR_MULT_DOSStub_21c4 {
  strings:
    $key_21c4 = { 75 ac [2] 01 b4 [2] 46 b6 [2] 01 a7 [2] 4f ab [2] 43 a1 [2] 54 aa [2] 4f e4 [2] 72 }

  condition:
    any of them
}