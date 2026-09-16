rule TTP_XOR_MULT_DOSStub_3d47 {
  strings:
    $key_3d47 = { 69 2f [2] 1d 37 [2] 5a 35 [2] 1d 24 [2] 53 28 [2] 5f 22 [2] 48 29 [2] 53 67 [2] 6e }

  condition:
    any of them
}