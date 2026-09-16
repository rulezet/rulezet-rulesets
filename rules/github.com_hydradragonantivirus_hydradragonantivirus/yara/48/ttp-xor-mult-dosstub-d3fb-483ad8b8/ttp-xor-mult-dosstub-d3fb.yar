rule TTP_XOR_MULT_DOSStub_d3fb {
  strings:
    $key_d3fb = { 87 93 [2] f3 8b [2] b4 89 [2] f3 98 [2] bd 94 [2] b1 9e [2] a6 95 [2] bd db [2] 80 }

  condition:
    any of them
}