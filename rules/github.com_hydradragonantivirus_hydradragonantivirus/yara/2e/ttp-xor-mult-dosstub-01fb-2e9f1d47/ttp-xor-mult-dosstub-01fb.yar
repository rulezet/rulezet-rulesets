rule TTP_XOR_MULT_DOSStub_01fb {
  strings:
    $key_01fb = { 55 93 [2] 21 8b [2] 66 89 [2] 21 98 [2] 6f 94 [2] 63 9e [2] 74 95 [2] 6f db [2] 52 }

  condition:
    any of them
}