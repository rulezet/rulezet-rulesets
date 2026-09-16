rule TTP_XOR_MULT_DOSStub_b307 {
  strings:
    $key_b307 = { e7 6f [2] 93 77 [2] d4 75 [2] 93 64 [2] dd 68 [2] d1 62 [2] c6 69 [2] dd 27 [2] e0 }

  condition:
    any of them
}