rule TTP_XOR_MULT_DOSStub_01b1 {
  strings:
    $key_01b1 = { 55 d9 [2] 21 c1 [2] 66 c3 [2] 21 d2 [2] 6f de [2] 63 d4 [2] 74 df [2] 6f 91 [2] 52 }

  condition:
    any of them
}