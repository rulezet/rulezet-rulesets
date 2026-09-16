rule TTP_XOR_MULT_DOSStub_e4c4 {
  strings:
    $key_e4c4 = { b0 ac [2] c4 b4 [2] 83 b6 [2] c4 a7 [2] 8a ab [2] 86 a1 [2] 91 aa [2] 8a e4 [2] b7 }

  condition:
    any of them
}