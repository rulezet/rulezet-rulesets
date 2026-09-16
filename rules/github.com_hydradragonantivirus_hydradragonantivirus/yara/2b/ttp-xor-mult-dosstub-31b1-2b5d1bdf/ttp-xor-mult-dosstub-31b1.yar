rule TTP_XOR_MULT_DOSStub_31b1 {
  strings:
    $key_31b1 = { 65 d9 [2] 11 c1 [2] 56 c3 [2] 11 d2 [2] 5f de [2] 53 d4 [2] 44 df [2] 5f 91 [2] 62 }

  condition:
    any of them
}