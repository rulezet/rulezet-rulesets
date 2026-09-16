rule TTP_XOR_MULT_DOSStub_b757 {
  strings:
    $key_b757 = { e3 3f [2] 97 27 [2] d0 25 [2] 97 34 [2] d9 38 [2] d5 32 [2] c2 39 [2] d9 77 [2] e4 }

  condition:
    any of them
}