rule TTP_XOR_MULT_DOSStub_30ec {
  strings:
    $key_30ec = { 64 84 [2] 10 9c [2] 57 9e [2] 10 8f [2] 5e 83 [2] 52 89 [2] 45 82 [2] 5e cc [2] 63 }

  condition:
    any of them
}