rule TTP_XOR_MULT_DOSStub_2d56 {
  strings:
    $key_2d56 = { 79 3e [2] 0d 26 [2] 4a 24 [2] 0d 35 [2] 43 39 [2] 4f 33 [2] 58 38 [2] 43 76 [2] 7e }

  condition:
    any of them
}