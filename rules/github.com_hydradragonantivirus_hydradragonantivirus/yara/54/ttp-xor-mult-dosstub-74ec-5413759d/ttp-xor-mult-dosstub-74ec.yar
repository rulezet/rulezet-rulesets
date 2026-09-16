rule TTP_XOR_MULT_DOSStub_74ec {
  strings:
    $key_74ec = { 20 84 [2] 54 9c [2] 13 9e [2] 54 8f [2] 1a 83 [2] 16 89 [2] 01 82 [2] 1a cc [2] 27 }

  condition:
    any of them
}