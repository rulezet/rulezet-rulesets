rule TTP_XOR_MULT_DOSStub_7156 {
  strings:
    $key_7156 = { 25 3e [2] 51 26 [2] 16 24 [2] 51 35 [2] 1f 39 [2] 13 33 [2] 04 38 [2] 1f 76 [2] 22 }

  condition:
    any of them
}