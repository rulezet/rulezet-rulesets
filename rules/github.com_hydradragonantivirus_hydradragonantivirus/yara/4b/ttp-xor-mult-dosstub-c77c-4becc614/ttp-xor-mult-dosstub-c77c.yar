rule TTP_XOR_MULT_DOSStub_c77c {
  strings:
    $key_c77c = { 93 14 [2] e7 0c [2] a0 0e [2] e7 1f [2] a9 13 [2] a5 19 [2] b2 12 [2] a9 5c [2] 94 }

  condition:
    any of them
}