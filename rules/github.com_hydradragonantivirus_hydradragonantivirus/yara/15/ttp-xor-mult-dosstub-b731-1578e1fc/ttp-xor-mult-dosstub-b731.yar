rule TTP_XOR_MULT_DOSStub_b731 {
  strings:
    $key_b731 = { e3 59 [2] 97 41 [2] d0 43 [2] 97 52 [2] d9 5e [2] d5 54 [2] c2 5f [2] d9 11 [2] e4 }

  condition:
    any of them
}