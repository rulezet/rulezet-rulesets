rule TTP_XOR_MULT_DOSStub_c71b {
  strings:
    $key_c71b = { 93 73 [2] e7 6b [2] a0 69 [2] e7 78 [2] a9 74 [2] a5 7e [2] b2 75 [2] a9 3b [2] 94 }

  condition:
    any of them
}