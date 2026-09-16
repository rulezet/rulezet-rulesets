rule TTP_XOR_MULT_DOSStub_4d47 {
  strings:
    $key_4d47 = { 19 2f [2] 6d 37 [2] 2a 35 [2] 6d 24 [2] 23 28 [2] 2f 22 [2] 38 29 [2] 23 67 [2] 1e }

  condition:
    any of them
}