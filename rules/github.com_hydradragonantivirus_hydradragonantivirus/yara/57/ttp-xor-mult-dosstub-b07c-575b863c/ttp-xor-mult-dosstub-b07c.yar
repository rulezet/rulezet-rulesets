rule TTP_XOR_MULT_DOSStub_b07c {
  strings:
    $key_b07c = { e4 14 [2] 90 0c [2] d7 0e [2] 90 1f [2] de 13 [2] d2 19 [2] c5 12 [2] de 5c [2] e3 }

  condition:
    any of them
}