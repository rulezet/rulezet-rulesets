rule TTP_XOR_MULT_DOSStub_4550 {
  strings:
    $key_4550 = { 11 38 [2] 65 20 [2] 22 22 [2] 65 33 [2] 2b 3f [2] 27 35 [2] 30 3e [2] 2b 70 [2] 16 }

  condition:
    any of them
}