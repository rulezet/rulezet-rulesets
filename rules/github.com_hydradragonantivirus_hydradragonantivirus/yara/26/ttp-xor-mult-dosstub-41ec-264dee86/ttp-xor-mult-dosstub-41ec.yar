rule TTP_XOR_MULT_DOSStub_41ec {
  strings:
    $key_41ec = { 15 84 [2] 61 9c [2] 26 9e [2] 61 8f [2] 2f 83 [2] 23 89 [2] 34 82 [2] 2f cc [2] 12 }

  condition:
    any of them
}