rule TTP_XOR_MULT_DOSStub_b726 {
  strings:
    $key_b726 = { e3 4e [2] 97 56 [2] d0 54 [2] 97 45 [2] d9 49 [2] d5 43 [2] c2 48 [2] d9 06 [2] e4 }

  condition:
    any of them
}