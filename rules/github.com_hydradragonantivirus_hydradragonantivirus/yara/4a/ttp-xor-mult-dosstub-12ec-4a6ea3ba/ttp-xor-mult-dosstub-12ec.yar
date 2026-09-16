rule TTP_XOR_MULT_DOSStub_12ec {
  strings:
    $key_12ec = { 46 84 [2] 32 9c [2] 75 9e [2] 32 8f [2] 7c 83 [2] 70 89 [2] 67 82 [2] 7c cc [2] 41 }

  condition:
    any of them
}