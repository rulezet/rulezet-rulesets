rule TTP_XOR_MULT_DOSStub_3d63 {
  strings:
    $key_3d63 = { 69 0b [2] 1d 13 [2] 5a 11 [2] 1d 00 [2] 53 0c [2] 5f 06 [2] 48 0d [2] 53 43 [2] 6e }

  condition:
    any of them
}