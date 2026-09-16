rule TTP_XOR_MULT_DOSStub_74c4 {
  strings:
    $key_74c4 = { 20 ac [2] 54 b4 [2] 13 b6 [2] 54 a7 [2] 1a ab [2] 16 a1 [2] 01 aa [2] 1a e4 [2] 27 }

  condition:
    any of them
}