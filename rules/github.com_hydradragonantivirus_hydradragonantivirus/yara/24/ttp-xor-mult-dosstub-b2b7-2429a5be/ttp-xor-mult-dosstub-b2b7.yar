rule TTP_XOR_MULT_DOSStub_b2b7 {
  strings:
    $key_b2b7 = { e6 df [2] 92 c7 [2] d5 c5 [2] 92 d4 [2] dc d8 [2] d0 d2 [2] c7 d9 [2] dc 97 [2] e1 }

  condition:
    any of them
}