rule TTP_XOR_MULT_DOSStub_0d1a {
  strings:
    $key_0d1a = { 59 72 [2] 2d 6a [2] 6a 68 [2] 2d 79 [2] 63 75 [2] 6f 7f [2] 78 74 [2] 63 3a [2] 5e }

  condition:
    any of them
}