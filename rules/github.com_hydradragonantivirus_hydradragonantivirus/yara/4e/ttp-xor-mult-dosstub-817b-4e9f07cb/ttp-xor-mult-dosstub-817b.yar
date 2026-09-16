rule TTP_XOR_MULT_DOSStub_817b {
  strings:
    $key_817b = { d5 13 [2] a1 0b [2] e6 09 [2] a1 18 [2] ef 14 [2] e3 1e [2] f4 15 [2] ef 5b [2] d2 }

  condition:
    any of them
}