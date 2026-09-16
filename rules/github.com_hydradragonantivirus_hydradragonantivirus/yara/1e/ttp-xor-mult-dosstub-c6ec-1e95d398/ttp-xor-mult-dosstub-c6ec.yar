rule TTP_XOR_MULT_DOSStub_c6ec {
  strings:
    $key_c6ec = { 92 84 [2] e6 9c [2] a1 9e [2] e6 8f [2] a8 83 [2] a4 89 [2] b3 82 [2] a8 cc [2] 95 }

  condition:
    any of them
}