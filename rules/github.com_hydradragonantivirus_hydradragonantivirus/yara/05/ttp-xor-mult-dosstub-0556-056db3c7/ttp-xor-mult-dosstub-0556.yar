rule TTP_XOR_MULT_DOSStub_0556 {
  strings:
    $key_0556 = { 51 3e [2] 25 26 [2] 62 24 [2] 25 35 [2] 6b 39 [2] 67 33 [2] 70 38 [2] 6b 76 [2] 56 }

  condition:
    any of them
}