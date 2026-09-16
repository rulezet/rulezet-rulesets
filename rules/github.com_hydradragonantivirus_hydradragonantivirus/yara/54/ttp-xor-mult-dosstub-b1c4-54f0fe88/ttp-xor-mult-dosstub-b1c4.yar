rule TTP_XOR_MULT_DOSStub_b1c4 {
  strings:
    $key_b1c4 = { e5 ac [2] 91 b4 [2] d6 b6 [2] 91 a7 [2] df ab [2] d3 a1 [2] c4 aa [2] df e4 [2] e2 }

  condition:
    any of them
}