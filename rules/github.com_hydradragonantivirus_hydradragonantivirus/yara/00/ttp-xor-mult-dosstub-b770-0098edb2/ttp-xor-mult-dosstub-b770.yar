rule TTP_XOR_MULT_DOSStub_b770 {
  strings:
    $key_b770 = { e3 18 [2] 97 00 [2] d0 02 [2] 97 13 [2] d9 1f [2] d5 15 [2] c2 1e [2] d9 50 [2] e4 }

  condition:
    any of them
}