rule TTP_XOR_MULT_DOSStub_c67d {
  strings:
    $key_c67d = { 92 15 [2] e6 0d [2] a1 0f [2] e6 1e [2] a8 12 [2] a4 18 [2] b3 13 [2] a8 5d [2] 95 }

  condition:
    any of them
}