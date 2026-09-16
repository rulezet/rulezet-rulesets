rule TTP_XOR_MULT_DOSStub_3d40 {
  strings:
    $key_3d40 = { 69 28 [2] 1d 30 [2] 5a 32 [2] 1d 23 [2] 53 2f [2] 5f 25 [2] 48 2e [2] 53 60 [2] 6e }

  condition:
    any of them
}