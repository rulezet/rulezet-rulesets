rule TTP_XOR_MULT_DOSStub_00ec {
  strings:
    $key_00ec = { 54 84 [2] 20 9c [2] 67 9e [2] 20 8f [2] 6e 83 [2] 62 89 [2] 75 82 [2] 6e cc [2] 53 }

  condition:
    any of them
}