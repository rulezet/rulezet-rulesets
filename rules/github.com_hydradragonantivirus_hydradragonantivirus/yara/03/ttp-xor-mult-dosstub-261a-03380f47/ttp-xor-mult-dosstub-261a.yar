rule TTP_XOR_MULT_DOSStub_261a {
  strings:
    $key_261a = { 72 72 [2] 06 6a [2] 41 68 [2] 06 79 [2] 48 75 [2] 44 7f [2] 53 74 [2] 48 3a [2] 75 }

  condition:
    any of them
}