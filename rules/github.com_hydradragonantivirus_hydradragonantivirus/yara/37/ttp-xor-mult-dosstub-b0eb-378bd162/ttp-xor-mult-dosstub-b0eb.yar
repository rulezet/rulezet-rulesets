rule TTP_XOR_MULT_DOSStub_b0eb {
  strings:
    $key_b0eb = { e4 83 [2] 90 9b [2] d7 99 [2] 90 88 [2] de 84 [2] d2 8e [2] c5 85 [2] de cb [2] e3 }

  condition:
    any of them
}