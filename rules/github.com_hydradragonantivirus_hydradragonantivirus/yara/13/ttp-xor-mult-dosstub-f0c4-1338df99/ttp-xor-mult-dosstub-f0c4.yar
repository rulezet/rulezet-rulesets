rule TTP_XOR_MULT_DOSStub_f0c4 {
  strings:
    $key_f0c4 = { a4 ac [2] d0 b4 [2] 97 b6 [2] d0 a7 [2] 9e ab [2] 92 a1 [2] 85 aa [2] 9e e4 [2] a3 }

  condition:
    any of them
}