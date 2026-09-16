rule TTP_XOR_MULT_DOSStub_3d46 {
  strings:
    $key_3d46 = { 69 2e [2] 1d 36 [2] 5a 34 [2] 1d 25 [2] 53 29 [2] 5f 23 [2] 48 28 [2] 53 66 [2] 6e }

  condition:
    any of them
}