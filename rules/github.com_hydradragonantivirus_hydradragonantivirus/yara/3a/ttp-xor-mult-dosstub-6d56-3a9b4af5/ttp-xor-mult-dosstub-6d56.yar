rule TTP_XOR_MULT_DOSStub_6d56 {
  strings:
    $key_6d56 = { 39 3e [2] 4d 26 [2] 0a 24 [2] 4d 35 [2] 03 39 [2] 0f 33 [2] 18 38 [2] 03 76 [2] 3e }

  condition:
    any of them
}