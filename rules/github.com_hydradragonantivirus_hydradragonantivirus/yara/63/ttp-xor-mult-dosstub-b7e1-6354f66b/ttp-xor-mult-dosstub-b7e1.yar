rule TTP_XOR_MULT_DOSStub_b7e1 {
  strings:
    $key_b7e1 = { e3 89 [2] 97 91 [2] d0 93 [2] 97 82 [2] d9 8e [2] d5 84 [2] c2 8f [2] d9 c1 [2] e4 }

  condition:
    any of them
}