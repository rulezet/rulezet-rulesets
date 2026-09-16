rule TTP_XOR_MULT_DOSStub_c65c {
  strings:
    $key_c65c = { 92 34 [2] e6 2c [2] a1 2e [2] e6 3f [2] a8 33 [2] a4 39 [2] b3 32 [2] a8 7c [2] 95 }

  condition:
    any of them
}