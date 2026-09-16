rule TTP_XOR_MULT_DOSStub_50ec {
  strings:
    $key_50ec = { 04 84 [2] 70 9c [2] 37 9e [2] 70 8f [2] 3e 83 [2] 32 89 [2] 25 82 [2] 3e cc [2] 03 }

  condition:
    any of them
}