rule TTP_XOR_MULT_DOSStub_541a {
  strings:
    $key_541a = { 00 72 [2] 74 6a [2] 33 68 [2] 74 79 [2] 3a 75 [2] 36 7f [2] 21 74 [2] 3a 3a [2] 07 }

  condition:
    any of them
}