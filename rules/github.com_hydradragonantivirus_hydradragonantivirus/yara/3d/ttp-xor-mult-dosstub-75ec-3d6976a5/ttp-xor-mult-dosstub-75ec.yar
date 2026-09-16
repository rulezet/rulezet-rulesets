rule TTP_XOR_MULT_DOSStub_75ec {
  strings:
    $key_75ec = { 21 84 [2] 55 9c [2] 12 9e [2] 55 8f [2] 1b 83 [2] 17 89 [2] 00 82 [2] 1b cc [2] 26 }

  condition:
    any of them
}