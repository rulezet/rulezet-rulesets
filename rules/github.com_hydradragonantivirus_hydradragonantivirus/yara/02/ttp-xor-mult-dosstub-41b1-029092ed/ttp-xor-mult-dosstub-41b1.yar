rule TTP_XOR_MULT_DOSStub_41b1 {
  strings:
    $key_41b1 = { 15 d9 [2] 61 c1 [2] 26 c3 [2] 61 d2 [2] 2f de [2] 23 d4 [2] 34 df [2] 2f 91 [2] 12 }

  condition:
    any of them
}