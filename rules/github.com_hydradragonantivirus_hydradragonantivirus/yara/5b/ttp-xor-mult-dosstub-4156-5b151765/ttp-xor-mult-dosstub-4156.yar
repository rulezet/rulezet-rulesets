rule TTP_XOR_MULT_DOSStub_4156 {
  strings:
    $key_4156 = { 15 3e [2] 61 26 [2] 26 24 [2] 61 35 [2] 2f 39 [2] 23 33 [2] 34 38 [2] 2f 76 [2] 12 }

  condition:
    any of them
}