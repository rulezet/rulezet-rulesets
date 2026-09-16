rule TTP_XOR_MULT_DOSStub_3d26 {
  strings:
    $key_3d26 = { 69 4e [2] 1d 56 [2] 5a 54 [2] 1d 45 [2] 53 49 [2] 5f 43 [2] 48 48 [2] 53 06 [2] 6e }

  condition:
    any of them
}