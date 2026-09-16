rule TTP_XOR_MULT_DOSStub_55ec {
  strings:
    $key_55ec = { 01 84 [2] 75 9c [2] 32 9e [2] 75 8f [2] 3b 83 [2] 37 89 [2] 20 82 [2] 3b cc [2] 06 }

  condition:
    any of them
}