rule TTP_XOR_MULT_DOSStub_451a {
  strings:
    $key_451a = { 11 72 [2] 65 6a [2] 22 68 [2] 65 79 [2] 2b 75 [2] 27 7f [2] 30 74 [2] 2b 3a [2] 16 }

  condition:
    any of them
}