rule TTP_XOR_MULT_DOSStub_4f3a {
  strings:
    $key_4f3a = { 1b 52 [2] 6f 4a [2] 28 48 [2] 6f 59 [2] 21 55 [2] 2d 5f [2] 3a 54 [2] 21 1a [2] 1c }

  condition:
    any of them
}