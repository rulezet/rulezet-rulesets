rule TTP_XOR_MULT_DOSStub_c64d {
  strings:
    $key_c64d = { 92 25 [2] e6 3d [2] a1 3f [2] e6 2e [2] a8 22 [2] a4 28 [2] b3 23 [2] a8 6d [2] 95 }

  condition:
    any of them
}