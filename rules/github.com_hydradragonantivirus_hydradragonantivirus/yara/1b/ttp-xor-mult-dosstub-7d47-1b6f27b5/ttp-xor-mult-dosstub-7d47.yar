rule TTP_XOR_MULT_DOSStub_7d47 {
  strings:
    $key_7d47 = { 29 2f [2] 5d 37 [2] 1a 35 [2] 5d 24 [2] 13 28 [2] 1f 22 [2] 08 29 [2] 13 67 [2] 2e }

  condition:
    any of them
}