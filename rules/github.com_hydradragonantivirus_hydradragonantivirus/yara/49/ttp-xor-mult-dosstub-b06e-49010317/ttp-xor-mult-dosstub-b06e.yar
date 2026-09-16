rule TTP_XOR_MULT_DOSStub_b06e {
  strings:
    $key_b06e = { e4 06 [2] 90 1e [2] d7 1c [2] 90 0d [2] de 01 [2] d2 0b [2] c5 00 [2] de 4e [2] e3 }

  condition:
    any of them
}