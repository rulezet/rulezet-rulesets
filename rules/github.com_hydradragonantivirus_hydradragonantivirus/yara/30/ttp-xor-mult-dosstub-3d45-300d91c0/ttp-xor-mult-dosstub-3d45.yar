rule TTP_XOR_MULT_DOSStub_3d45 {
  strings:
    $key_3d45 = { 69 2d [2] 1d 35 [2] 5a 37 [2] 1d 26 [2] 53 2a [2] 5f 20 [2] 48 2b [2] 53 65 [2] 6e }

  condition:
    any of them
}