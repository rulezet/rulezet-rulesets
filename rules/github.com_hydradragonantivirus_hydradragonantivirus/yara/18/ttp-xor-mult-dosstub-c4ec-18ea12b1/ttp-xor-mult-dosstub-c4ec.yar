rule TTP_XOR_MULT_DOSStub_c4ec {
  strings:
    $key_c4ec = { 90 84 [2] e4 9c [2] a3 9e [2] e4 8f [2] aa 83 [2] a6 89 [2] b1 82 [2] aa cc [2] 97 }

  condition:
    any of them
}