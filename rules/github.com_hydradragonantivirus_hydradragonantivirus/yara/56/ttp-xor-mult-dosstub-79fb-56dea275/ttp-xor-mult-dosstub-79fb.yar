rule TTP_XOR_MULT_DOSStub_79fb {
  strings:
    $key_79fb = { 2d 93 [2] 59 8b [2] 1e 89 [2] 59 98 [2] 17 94 [2] 1b 9e [2] 0c 95 [2] 17 db [2] 2a }

  condition:
    any of them
}