rule TTP_XOR_MULT_DOSStub_3d54 {
  strings:
    $key_3d54 = { 69 3c [2] 1d 24 [2] 5a 26 [2] 1d 37 [2] 53 3b [2] 5f 31 [2] 48 3a [2] 53 74 [2] 6e }

  condition:
    any of them
}