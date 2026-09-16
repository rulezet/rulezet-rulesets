rule TTP_XOR_MULT_DOSStub_24ec {
  strings:
    $key_24ec = { 70 84 [2] 04 9c [2] 43 9e [2] 04 8f [2] 4a 83 [2] 46 89 [2] 51 82 [2] 4a cc [2] 77 }

  condition:
    any of them
}