rule TTP_XOR_MULT_DOSStub_051a {
  strings:
    $key_051a = { 51 72 [2] 25 6a [2] 62 68 [2] 25 79 [2] 6b 75 [2] 67 7f [2] 70 74 [2] 6b 3a [2] 56 }

  condition:
    any of them
}