rule TTP_XOR_MULT_DOSStub_b061 {
  strings:
    $key_b061 = { e4 09 [2] 90 11 [2] d7 13 [2] 90 02 [2] de 0e [2] d2 04 [2] c5 0f [2] de 41 [2] e3 }

  condition:
    any of them
}