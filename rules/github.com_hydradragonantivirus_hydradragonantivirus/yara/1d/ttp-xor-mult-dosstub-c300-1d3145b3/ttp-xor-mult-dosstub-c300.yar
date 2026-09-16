rule TTP_XOR_MULT_DOSStub_c300 {
  strings:
    $key_c300 = { 97 68 [2] e3 70 [2] a4 72 [2] e3 63 [2] ad 6f [2] a1 65 [2] b6 6e [2] ad 20 [2] 90 }

  condition:
    any of them
}