rule TTP_XOR_MULT_DOSStub_c320 {
  strings:
    $key_c320 = { 97 48 [2] e3 50 [2] a4 52 [2] e3 43 [2] ad 4f [2] a1 45 [2] b6 4e [2] ad 00 [2] 90 }

  condition:
    any of them
}