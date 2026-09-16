rule TTP_XOR_MULT_DOSStub_c44e {
  strings:
    $key_c44e = { 90 26 [2] e4 3e [2] a3 3c [2] e4 2d [2] aa 21 [2] a6 2b [2] b1 20 [2] aa 6e [2] 97 }

  condition:
    any of them
}