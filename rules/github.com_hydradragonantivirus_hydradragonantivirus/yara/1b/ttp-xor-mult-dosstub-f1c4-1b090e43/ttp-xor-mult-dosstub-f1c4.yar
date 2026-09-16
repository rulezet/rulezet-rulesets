rule TTP_XOR_MULT_DOSStub_f1c4 {
  strings:
    $key_f1c4 = { a5 ac [2] d1 b4 [2] 96 b6 [2] d1 a7 [2] 9f ab [2] 93 a1 [2] 84 aa [2] 9f e4 [2] a2 }

  condition:
    any of them
}