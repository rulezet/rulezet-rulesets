rule TTP_XOR_MULT_DOSStub_e4fb {
  strings:
    $key_e4fb = { b0 93 [2] c4 8b [2] 83 89 [2] c4 98 [2] 8a 94 [2] 86 9e [2] 91 95 [2] 8a db [2] b7 }

  condition:
    any of them
}