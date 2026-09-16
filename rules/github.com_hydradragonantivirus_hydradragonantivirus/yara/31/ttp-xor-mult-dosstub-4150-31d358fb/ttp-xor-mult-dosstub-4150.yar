rule TTP_XOR_MULT_DOSStub_4150 {
  strings:
    $key_4150 = { 15 38 [2] 61 20 [2] 26 22 [2] 61 33 [2] 2f 3f [2] 23 35 [2] 34 3e [2] 2f 70 [2] 12 }

  condition:
    any of them
}