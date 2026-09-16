rule TTP_XOR_MULT_DOSStub_4d56 {
  strings:
    $key_4d56 = { 19 3e [2] 6d 26 [2] 2a 24 [2] 6d 35 [2] 23 39 [2] 2f 33 [2] 38 38 [2] 23 76 [2] 1e }

  condition:
    any of them
}