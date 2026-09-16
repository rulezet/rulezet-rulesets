rule TTP_XOR_MULT_DOSStub_07ec {
  strings:
    $key_07ec = { 53 84 [2] 27 9c [2] 60 9e [2] 27 8f [2] 69 83 [2] 65 89 [2] 72 82 [2] 69 cc [2] 54 }

  condition:
    any of them
}