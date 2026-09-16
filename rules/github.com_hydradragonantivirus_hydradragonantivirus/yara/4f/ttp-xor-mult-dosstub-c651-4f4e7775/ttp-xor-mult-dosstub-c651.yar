rule TTP_XOR_MULT_DOSStub_c651 {
  strings:
    $key_c651 = { 92 39 [2] e6 21 [2] a1 23 [2] e6 32 [2] a8 3e [2] a4 34 [2] b3 3f [2] a8 71 [2] 95 }

  condition:
    any of them
}