rule TTP_XOR_MULT_DOSStub_4f4a {
  strings:
    $key_4f4a = { 1b 22 [2] 6f 3a [2] 28 38 [2] 6f 29 [2] 21 25 [2] 2d 2f [2] 3a 24 [2] 21 6a [2] 1c }

  condition:
    any of them
}