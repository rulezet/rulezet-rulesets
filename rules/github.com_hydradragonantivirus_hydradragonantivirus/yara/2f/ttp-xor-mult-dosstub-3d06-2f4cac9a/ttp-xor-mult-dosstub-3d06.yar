rule TTP_XOR_MULT_DOSStub_3d06 {
  strings:
    $key_3d06 = { 69 6e [2] 1d 76 [2] 5a 74 [2] 1d 65 [2] 53 69 [2] 5f 63 [2] 48 68 [2] 53 26 [2] 6e }

  condition:
    any of them
}