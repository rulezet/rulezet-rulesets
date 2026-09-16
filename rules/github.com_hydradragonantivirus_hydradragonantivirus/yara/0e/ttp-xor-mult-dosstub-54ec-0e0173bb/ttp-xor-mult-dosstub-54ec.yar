rule TTP_XOR_MULT_DOSStub_54ec {
  strings:
    $key_54ec = { 00 84 [2] 74 9c [2] 33 9e [2] 74 8f [2] 3a 83 [2] 36 89 [2] 21 82 [2] 3a cc [2] 07 }

  condition:
    any of them
}