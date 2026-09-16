rule TTP_XOR_MULT_DOSStub_583a {
  strings:
    $key_583a = { 0c 52 [2] 78 4a [2] 3f 48 [2] 78 59 [2] 36 55 [2] 3a 5f [2] 2d 54 [2] 36 1a [2] 0b }

  condition:
    any of them
}