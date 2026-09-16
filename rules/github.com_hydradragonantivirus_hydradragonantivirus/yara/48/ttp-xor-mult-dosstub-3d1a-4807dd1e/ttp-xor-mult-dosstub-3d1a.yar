rule TTP_XOR_MULT_DOSStub_3d1a {
  strings:
    $key_3d1a = { 69 72 [2] 1d 6a [2] 5a 68 [2] 1d 79 [2] 53 75 [2] 5f 7f [2] 48 74 [2] 53 3a [2] 6e }

  condition:
    any of them
}