rule TTP_XOR_MULT_DOSStub_c76b {
  strings:
    $key_c76b = { 93 03 [2] e7 1b [2] a0 19 [2] e7 08 [2] a9 04 [2] a5 0e [2] b2 05 [2] a9 4b [2] 94 }

  condition:
    any of them
}