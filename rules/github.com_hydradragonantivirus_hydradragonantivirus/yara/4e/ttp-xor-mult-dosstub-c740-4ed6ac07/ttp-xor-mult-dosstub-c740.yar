rule TTP_XOR_MULT_DOSStub_c740 {
  strings:
    $key_c740 = { 93 28 [2] e7 30 [2] a0 32 [2] e7 23 [2] a9 2f [2] a5 25 [2] b2 2e [2] a9 60 [2] 94 }

  condition:
    any of them
}