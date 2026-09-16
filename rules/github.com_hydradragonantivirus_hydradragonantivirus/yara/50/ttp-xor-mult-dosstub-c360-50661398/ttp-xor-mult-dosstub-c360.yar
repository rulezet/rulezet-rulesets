rule TTP_XOR_MULT_DOSStub_c360 {
  strings:
    $key_c360 = { 97 08 [2] e3 10 [2] a4 12 [2] e3 03 [2] ad 0f [2] a1 05 [2] b6 0e [2] ad 40 [2] 90 }

  condition:
    any of them
}