rule TTP_XOR_MULT_DOSStub_441a {
  strings:
    $key_441a = { 10 72 [2] 64 6a [2] 23 68 [2] 64 79 [2] 2a 75 [2] 26 7f [2] 31 74 [2] 2a 3a [2] 17 }

  condition:
    any of them
}