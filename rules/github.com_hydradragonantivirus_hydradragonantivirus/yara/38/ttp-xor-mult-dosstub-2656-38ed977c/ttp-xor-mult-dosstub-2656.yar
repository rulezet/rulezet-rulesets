rule TTP_XOR_MULT_DOSStub_2656 {
  strings:
    $key_2656 = { 72 3e [2] 06 26 [2] 41 24 [2] 06 35 [2] 48 39 [2] 44 33 [2] 53 38 [2] 48 76 [2] 75 }

  condition:
    any of them
}