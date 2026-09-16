rule TTP_XOR_MULT_DOSStub_b0ed {
  strings:
    $key_b0ed = { e4 85 [2] 90 9d [2] d7 9f [2] 90 8e [2] de 82 [2] d2 88 [2] c5 83 [2] de cd [2] e3 }

  condition:
    any of them
}