rule TTP_XOR_MULT_DOSStub_7d50 {
  strings:
    $key_7d50 = { 29 38 [2] 5d 20 [2] 1a 22 [2] 5d 33 [2] 13 3f [2] 1f 35 [2] 08 3e [2] 13 70 [2] 2e }

  condition:
    any of them
}