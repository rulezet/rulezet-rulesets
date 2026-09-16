rule TTP_XOR_MULT_DOSStub_c0fb {
  strings:
    $key_c0fb = { 94 93 [2] e0 8b [2] a7 89 [2] e0 98 [2] ae 94 [2] a2 9e [2] b5 95 [2] ae db [2] 93 }

  condition:
    any of them
}