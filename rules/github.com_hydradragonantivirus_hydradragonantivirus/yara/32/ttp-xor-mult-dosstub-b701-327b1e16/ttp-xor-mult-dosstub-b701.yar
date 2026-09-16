rule TTP_XOR_MULT_DOSStub_b701 {
  strings:
    $key_b701 = { e3 69 [2] 97 71 [2] d0 73 [2] 97 62 [2] d9 6e [2] d5 64 [2] c2 6f [2] d9 21 [2] e4 }

  condition:
    any of them
}