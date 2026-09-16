rule TTP_XOR_MULT_DOSStub_24c4 {
  strings:
    $key_24c4 = { 70 ac [2] 04 b4 [2] 43 b6 [2] 04 a7 [2] 4a ab [2] 46 a1 [2] 51 aa [2] 4a e4 [2] 77 }

  condition:
    any of them
}