rule TTP_XOR_MULT_DOSStub_3556 {
  strings:
    $key_3556 = { 61 3e [2] 15 26 [2] 52 24 [2] 15 35 [2] 5b 39 [2] 57 33 [2] 40 38 [2] 5b 76 [2] 66 }

  condition:
    any of them
}