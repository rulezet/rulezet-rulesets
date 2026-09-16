rule TTP_XOR_MULT_DOSStub_e5fb {
  strings:
    $key_e5fb = { b1 93 [2] c5 8b [2] 82 89 [2] c5 98 [2] 8b 94 [2] 87 9e [2] 90 95 [2] 8b db [2] b6 }

  condition:
    any of them
}