rule TTP_XOR_MULT_DOSStub_b77d {
  strings:
    $key_b77d = { e3 15 [2] 97 0d [2] d0 0f [2] 97 1e [2] d9 12 [2] d5 18 [2] c2 13 [2] d9 5d [2] e4 }

  condition:
    any of them
}