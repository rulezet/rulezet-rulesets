rule TTP_XOR_MULT_DOSStub_3d55 {
  strings:
    $key_3d55 = { 69 3d [2] 1d 25 [2] 5a 27 [2] 1d 36 [2] 53 3a [2] 5f 30 [2] 48 3b [2] 53 75 [2] 6e }

  condition:
    any of them
}