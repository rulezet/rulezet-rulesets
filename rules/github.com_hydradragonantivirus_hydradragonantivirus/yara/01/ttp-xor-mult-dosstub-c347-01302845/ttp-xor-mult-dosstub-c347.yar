rule TTP_XOR_MULT_DOSStub_c347 {
  strings:
    $key_c347 = { 97 2f [2] e3 37 [2] a4 35 [2] e3 24 [2] ad 28 [2] a1 22 [2] b6 29 [2] ad 67 [2] 90 }

  condition:
    any of them
}