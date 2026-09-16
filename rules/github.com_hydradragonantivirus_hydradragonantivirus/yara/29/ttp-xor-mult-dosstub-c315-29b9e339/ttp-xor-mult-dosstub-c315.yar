rule TTP_XOR_MULT_DOSStub_c315 {
  strings:
    $key_c315 = { 97 7d [2] e3 65 [2] a4 67 [2] e3 76 [2] ad 7a [2] a1 70 [2] b6 7b [2] ad 35 [2] 90 }

  condition:
    any of them
}