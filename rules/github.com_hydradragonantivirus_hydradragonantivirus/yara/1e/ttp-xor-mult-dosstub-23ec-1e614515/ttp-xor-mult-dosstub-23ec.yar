rule TTP_XOR_MULT_DOSStub_23ec {
  strings:
    $key_23ec = { 77 84 [2] 03 9c [2] 44 9e [2] 03 8f [2] 4d 83 [2] 41 89 [2] 56 82 [2] 4d cc [2] 70 }

  condition:
    any of them
}