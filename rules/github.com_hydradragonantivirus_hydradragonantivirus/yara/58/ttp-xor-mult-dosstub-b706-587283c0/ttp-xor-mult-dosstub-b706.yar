rule TTP_XOR_MULT_DOSStub_b706 {
  strings:
    $key_b706 = { e3 6e [2] 97 76 [2] d0 74 [2] 97 65 [2] d9 69 [2] d5 63 [2] c2 68 [2] d9 26 [2] e4 }

  condition:
    any of them
}