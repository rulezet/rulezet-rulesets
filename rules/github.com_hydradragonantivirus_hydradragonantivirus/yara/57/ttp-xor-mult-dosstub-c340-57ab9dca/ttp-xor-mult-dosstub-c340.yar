rule TTP_XOR_MULT_DOSStub_c340 {
  strings:
    $key_c340 = { 97 28 [2] e3 30 [2] a4 32 [2] e3 23 [2] ad 2f [2] a1 25 [2] b6 2e [2] ad 60 [2] 90 }

  condition:
    any of them
}