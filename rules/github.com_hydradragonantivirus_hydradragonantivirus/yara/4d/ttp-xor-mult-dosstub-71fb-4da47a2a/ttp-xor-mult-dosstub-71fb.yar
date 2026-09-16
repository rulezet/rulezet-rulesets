rule TTP_XOR_MULT_DOSStub_71fb {
  strings:
    $key_71fb = { 25 93 [2] 51 8b [2] 16 89 [2] 51 98 [2] 1f 94 [2] 13 9e [2] 04 95 [2] 1f db [2] 22 }

  condition:
    any of them
}