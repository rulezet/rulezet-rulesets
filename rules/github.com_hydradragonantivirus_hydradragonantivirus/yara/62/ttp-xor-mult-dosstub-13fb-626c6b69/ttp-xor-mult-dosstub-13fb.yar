rule TTP_XOR_MULT_DOSStub_13fb {
  strings:
    $key_13fb = { 47 93 [2] 33 8b [2] 74 89 [2] 33 98 [2] 7d 94 [2] 71 9e [2] 66 95 [2] 7d db [2] 40 }

  condition:
    any of them
}