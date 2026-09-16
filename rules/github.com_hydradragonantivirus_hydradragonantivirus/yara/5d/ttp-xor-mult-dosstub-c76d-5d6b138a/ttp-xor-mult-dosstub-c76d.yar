rule TTP_XOR_MULT_DOSStub_c76d {
  strings:
    $key_c76d = { 93 05 [2] e7 1d [2] a0 1f [2] e7 0e [2] a9 02 [2] a5 08 [2] b2 03 [2] a9 4d [2] 94 }

  condition:
    any of them
}