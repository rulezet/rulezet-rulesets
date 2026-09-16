rule TTP_XOR_MULT_DOSStub_5d47 {
  strings:
    $key_5d47 = { 09 2f [2] 7d 37 [2] 3a 35 [2] 7d 24 [2] 33 28 [2] 3f 22 [2] 28 29 [2] 33 67 [2] 0e }

  condition:
    any of them
}