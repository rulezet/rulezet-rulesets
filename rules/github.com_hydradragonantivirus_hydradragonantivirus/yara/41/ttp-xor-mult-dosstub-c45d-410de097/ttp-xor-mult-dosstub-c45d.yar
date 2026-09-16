rule TTP_XOR_MULT_DOSStub_c45d {
  strings:
    $key_c45d = { 90 35 [2] e4 2d [2] a3 2f [2] e4 3e [2] aa 32 [2] a6 38 [2] b1 33 [2] aa 7d [2] 97 }

  condition:
    any of them
}