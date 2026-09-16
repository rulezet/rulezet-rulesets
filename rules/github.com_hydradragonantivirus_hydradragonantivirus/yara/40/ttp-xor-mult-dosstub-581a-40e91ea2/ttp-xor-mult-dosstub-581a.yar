rule TTP_XOR_MULT_DOSStub_581a {
  strings:
    $key_581a = { 0c 72 [2] 78 6a [2] 3f 68 [2] 78 79 [2] 36 75 [2] 3a 7f [2] 2d 74 [2] 36 3a [2] 0b }

  condition:
    any of them
}