rule TTP_XOR_MULT_DOSStub_c336 {
  strings:
    $key_c336 = { 97 5e [2] e3 46 [2] a4 44 [2] e3 55 [2] ad 59 [2] a1 53 [2] b6 58 [2] ad 16 [2] 90 }

  condition:
    any of them
}