rule TTP_XOR_MULT_DOSStub_b2b1 {
  strings:
    $key_b2b1 = { e6 d9 [2] 92 c1 [2] d5 c3 [2] 92 d2 [2] dc de [2] d0 d4 [2] c7 df [2] dc 91 [2] e1 }

  condition:
    any of them
}