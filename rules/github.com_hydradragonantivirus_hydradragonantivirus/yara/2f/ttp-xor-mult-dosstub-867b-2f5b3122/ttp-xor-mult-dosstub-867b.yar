rule TTP_XOR_MULT_DOSStub_867b {
  strings:
    $key_867b = { d2 13 [2] a6 0b [2] e1 09 [2] a6 18 [2] e8 14 [2] e4 1e [2] f3 15 [2] e8 5b [2] d5 }

  condition:
    any of them
}