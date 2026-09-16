rule TTP_XOR_MULT_DOSStub_3d52 {
  strings:
    $key_3d52 = { 69 3a [2] 1d 22 [2] 5a 20 [2] 1d 31 [2] 53 3d [2] 5f 37 [2] 48 3c [2] 53 72 [2] 6e }

  condition:
    any of them
}