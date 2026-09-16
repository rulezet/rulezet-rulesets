rule TTP_XOR_MULT_DOSStub_3d2a {
  strings:
    $key_3d2a = { 69 42 [2] 1d 5a [2] 5a 58 [2] 1d 49 [2] 53 45 [2] 5f 4f [2] 48 44 [2] 53 0a [2] 6e }

  condition:
    any of them
}