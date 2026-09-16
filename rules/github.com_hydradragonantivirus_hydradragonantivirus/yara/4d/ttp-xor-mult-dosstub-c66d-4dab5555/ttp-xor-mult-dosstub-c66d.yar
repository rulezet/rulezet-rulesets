rule TTP_XOR_MULT_DOSStub_c66d {
  strings:
    $key_c66d = { 92 05 [2] e6 1d [2] a1 1f [2] e6 0e [2] a8 02 [2] a4 08 [2] b3 03 [2] a8 4d [2] 95 }

  condition:
    any of them
}