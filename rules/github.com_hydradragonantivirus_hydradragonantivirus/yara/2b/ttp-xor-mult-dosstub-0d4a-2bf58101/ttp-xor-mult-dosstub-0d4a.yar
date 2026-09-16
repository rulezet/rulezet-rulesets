rule TTP_XOR_MULT_DOSStub_0d4a {
  strings:
    $key_0d4a = { 59 22 [2] 2d 3a [2] 6a 38 [2] 2d 29 [2] 63 25 [2] 6f 2f [2] 78 24 [2] 63 6a [2] 5e }

  condition:
    any of them
}