rule TTP_XOR_MULT_DOSStub_33ec {
  strings:
    $key_33ec = { 67 84 [2] 13 9c [2] 54 9e [2] 13 8f [2] 5d 83 [2] 51 89 [2] 46 82 [2] 5d cc [2] 60 }

  condition:
    any of them
}