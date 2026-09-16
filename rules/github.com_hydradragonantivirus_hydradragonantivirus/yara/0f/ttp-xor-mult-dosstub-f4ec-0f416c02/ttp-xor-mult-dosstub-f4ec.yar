rule TTP_XOR_MULT_DOSStub_f4ec {
  strings:
    $key_f4ec = { a0 84 [2] d4 9c [2] 93 9e [2] d4 8f [2] 9a 83 [2] 96 89 [2] 81 82 [2] 9a cc [2] a7 }

  condition:
    any of them
}