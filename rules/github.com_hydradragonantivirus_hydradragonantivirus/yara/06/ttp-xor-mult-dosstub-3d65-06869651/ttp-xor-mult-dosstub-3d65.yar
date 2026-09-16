rule TTP_XOR_MULT_DOSStub_3d65 {
  strings:
    $key_3d65 = { 69 0d [2] 1d 15 [2] 5a 17 [2] 1d 06 [2] 53 0a [2] 5f 00 [2] 48 0b [2] 53 45 [2] 6e }

  condition:
    any of them
}