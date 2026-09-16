rule TTP_XOR_MULT_DOSStub_b01b {
  strings:
    $key_b01b = { e4 73 [2] 90 6b [2] d7 69 [2] 90 78 [2] de 74 [2] d2 7e [2] c5 75 [2] de 3b [2] e3 }

  condition:
    any of them
}