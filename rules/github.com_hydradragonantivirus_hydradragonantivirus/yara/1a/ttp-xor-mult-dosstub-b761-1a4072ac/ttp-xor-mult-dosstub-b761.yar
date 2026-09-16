rule TTP_XOR_MULT_DOSStub_b761 {
  strings:
    $key_b761 = { e3 09 [2] 97 11 [2] d0 13 [2] 97 02 [2] d9 0e [2] d5 04 [2] c2 0f [2] d9 41 [2] e4 }

  condition:
    any of them
}