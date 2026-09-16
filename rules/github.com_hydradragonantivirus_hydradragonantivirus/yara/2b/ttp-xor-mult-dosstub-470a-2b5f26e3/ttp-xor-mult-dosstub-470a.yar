rule TTP_XOR_MULT_DOSStub_470a {
  strings:
    $key_470a = { 13 62 [2] 67 7a [2] 20 78 [2] 67 69 [2] 29 65 [2] 25 6f [2] 32 64 [2] 29 2a [2] 14 }

  condition:
    any of them
}