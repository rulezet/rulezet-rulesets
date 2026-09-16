rule TTP_XOR_MULT_DOSStub_b747 {
  strings:
    $key_b747 = { e3 2f [2] 97 37 [2] d0 35 [2] 97 24 [2] d9 28 [2] d5 22 [2] c2 29 [2] d9 67 [2] e4 }

  condition:
    any of them
}