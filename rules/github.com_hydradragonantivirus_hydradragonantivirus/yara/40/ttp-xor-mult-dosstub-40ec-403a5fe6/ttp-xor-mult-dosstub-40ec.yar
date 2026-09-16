rule TTP_XOR_MULT_DOSStub_40ec {
  strings:
    $key_40ec = { 14 84 [2] 60 9c [2] 27 9e [2] 60 8f [2] 2e 83 [2] 22 89 [2] 35 82 [2] 2e cc [2] 13 }

  condition:
    any of them
}