rule TTP_XOR_MULT_DOSStub_5d56 {
  strings:
    $key_5d56 = { 09 3e [2] 7d 26 [2] 3a 24 [2] 7d 35 [2] 33 39 [2] 3f 33 [2] 28 38 [2] 33 76 [2] 0e }

  condition:
    any of them
}