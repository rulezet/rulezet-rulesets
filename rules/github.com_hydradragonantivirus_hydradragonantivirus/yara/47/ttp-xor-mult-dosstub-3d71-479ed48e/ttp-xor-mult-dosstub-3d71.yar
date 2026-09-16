rule TTP_XOR_MULT_DOSStub_3d71 {
  strings:
    $key_3d71 = { 69 19 [2] 1d 01 [2] 5a 03 [2] 1d 12 [2] 53 1e [2] 5f 14 [2] 48 1f [2] 53 51 [2] 6e }

  condition:
    any of them
}