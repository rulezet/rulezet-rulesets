rule TTP_XOR_MULT_DOSStub_b7e6 {
  strings:
    $key_b7e6 = { e3 8e [2] 97 96 [2] d0 94 [2] 97 85 [2] d9 89 [2] d5 83 [2] c2 88 [2] d9 c6 [2] e4 }

  condition:
    any of them
}