rule TTP_XOR_MULT_DOSStub_14ec {
  strings:
    $key_14ec = { 40 84 [2] 34 9c [2] 73 9e [2] 34 8f [2] 7a 83 [2] 76 89 [2] 61 82 [2] 7a cc [2] 47 }

  condition:
    any of them
}