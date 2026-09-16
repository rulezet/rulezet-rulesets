rule TTP_XOR_MULT_DOSStub_c4fb {
  strings:
    $key_c4fb = { 90 93 [2] e4 8b [2] a3 89 [2] e4 98 [2] aa 94 [2] a6 9e [2] b1 95 [2] aa db [2] 97 }

  condition:
    any of them
}