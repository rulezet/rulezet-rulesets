rule TTP_XOR_MULT_DOSStub_e0c2 {
  strings:
    $key_e0c2 = { b4 aa [2] c0 b2 [2] 87 b0 [2] c0 a1 [2] 8e ad [2] 82 a7 [2] 95 ac [2] 8e e2 [2] b3 }

  condition:
    any of them
}