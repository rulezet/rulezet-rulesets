rule TTP_XOR_MULT_DOSStub_540a {
  strings:
    $key_540a = { 00 62 [2] 74 7a [2] 33 78 [2] 74 69 [2] 3a 65 [2] 36 6f [2] 21 64 [2] 3a 2a [2] 07 }

  condition:
    any of them
}