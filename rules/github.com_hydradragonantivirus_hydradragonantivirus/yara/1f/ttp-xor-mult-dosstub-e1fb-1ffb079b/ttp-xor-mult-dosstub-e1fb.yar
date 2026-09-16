rule TTP_XOR_MULT_DOSStub_e1fb {
  strings:
    $key_e1fb = { b5 93 [2] c1 8b [2] 86 89 [2] c1 98 [2] 8f 94 [2] 83 9e [2] 94 95 [2] 8f db [2] b2 }

  condition:
    any of them
}