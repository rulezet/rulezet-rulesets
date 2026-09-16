rule TTP_XOR_MULT_DOSStub_861b {
  strings:
    $key_861b = { d2 73 [2] a6 6b [2] e1 69 [2] a6 78 [2] e8 74 [2] e4 7e [2] f3 75 [2] e8 3b [2] d5 }

  condition:
    any of them
}