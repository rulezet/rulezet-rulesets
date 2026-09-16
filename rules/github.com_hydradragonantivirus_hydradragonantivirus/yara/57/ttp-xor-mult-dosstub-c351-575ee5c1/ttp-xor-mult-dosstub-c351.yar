rule TTP_XOR_MULT_DOSStub_c351 {
  strings:
    $key_c351 = { 97 39 [2] e3 21 [2] a4 23 [2] e3 32 [2] ad 3e [2] a1 34 [2] b6 3f [2] ad 71 [2] 90 }

  condition:
    any of them
}