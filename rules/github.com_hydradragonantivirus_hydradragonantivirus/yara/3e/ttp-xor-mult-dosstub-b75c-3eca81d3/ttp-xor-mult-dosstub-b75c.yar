rule TTP_XOR_MULT_DOSStub_b75c {
  strings:
    $key_b75c = { e3 34 [2] 97 2c [2] d0 2e [2] 97 3f [2] d9 33 [2] d5 39 [2] c2 32 [2] d9 7c [2] e4 }

  condition:
    any of them
}