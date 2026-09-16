rule TTP_XOR_MULT_DOSStub_44ec {
  strings:
    $key_44ec = { 10 84 [2] 64 9c [2] 23 9e [2] 64 8f [2] 2a 83 [2] 26 89 [2] 31 82 [2] 2a cc [2] 17 }

  condition:
    any of them
}