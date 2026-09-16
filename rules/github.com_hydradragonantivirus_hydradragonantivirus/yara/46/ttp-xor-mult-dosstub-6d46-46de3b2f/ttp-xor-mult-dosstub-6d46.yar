rule TTP_XOR_MULT_DOSStub_6d46 {
  strings:
    $key_6d46 = { 39 2e [2] 4d 36 [2] 0a 34 [2] 4d 25 [2] 03 29 [2] 0f 23 [2] 18 28 [2] 03 66 [2] 3e }

  condition:
    any of them
}