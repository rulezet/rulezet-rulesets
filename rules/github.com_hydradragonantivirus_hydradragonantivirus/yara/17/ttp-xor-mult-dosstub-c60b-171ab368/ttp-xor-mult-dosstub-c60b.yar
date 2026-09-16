rule TTP_XOR_MULT_DOSStub_c60b {
  strings:
    $key_c60b = { 92 63 [2] e6 7b [2] a1 79 [2] e6 68 [2] a8 64 [2] a4 6e [2] b3 65 [2] a8 2b [2] 95 }

  condition:
    any of them
}