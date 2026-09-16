rule TTP_XOR_MULT_DOSStub_11ec {
  strings:
    $key_11ec = { 45 84 [2] 31 9c [2] 76 9e [2] 31 8f [2] 7f 83 [2] 73 89 [2] 64 82 [2] 7f cc [2] 42 }

  condition:
    any of them
}