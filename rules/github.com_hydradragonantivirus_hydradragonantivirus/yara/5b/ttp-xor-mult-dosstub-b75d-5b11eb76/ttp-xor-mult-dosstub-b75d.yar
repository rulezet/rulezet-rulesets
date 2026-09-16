rule TTP_XOR_MULT_DOSStub_b75d {
  strings:
    $key_b75d = { e3 35 [2] 97 2d [2] d0 2f [2] 97 3e [2] d9 32 [2] d5 38 [2] c2 33 [2] d9 7d [2] e4 }

  condition:
    any of them
}