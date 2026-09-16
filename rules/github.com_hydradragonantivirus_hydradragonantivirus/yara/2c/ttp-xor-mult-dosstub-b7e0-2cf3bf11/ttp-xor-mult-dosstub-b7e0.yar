rule TTP_XOR_MULT_DOSStub_b7e0 {
  strings:
    $key_b7e0 = { e3 88 [2] 97 90 [2] d0 92 [2] 97 83 [2] d9 8f [2] d5 85 [2] c2 8e [2] d9 c0 [2] e4 }

  condition:
    any of them
}