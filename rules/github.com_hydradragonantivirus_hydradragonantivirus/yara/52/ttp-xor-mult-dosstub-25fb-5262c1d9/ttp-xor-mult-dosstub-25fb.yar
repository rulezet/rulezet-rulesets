rule TTP_XOR_MULT_DOSStub_25fb {
  strings:
    $key_25fb = { 71 93 [2] 05 8b [2] 42 89 [2] 05 98 [2] 4b 94 [2] 47 9e [2] 50 95 [2] 4b db [2] 76 }

  condition:
    any of them
}