rule TTP_XOR_MULT_DOSStub_c7ec {
  strings:
    $key_c7ec = { 93 84 [2] e7 9c [2] a0 9e [2] e7 8f [2] a9 83 [2] a5 89 [2] b2 82 [2] a9 cc [2] 94 }

  condition:
    any of them
}