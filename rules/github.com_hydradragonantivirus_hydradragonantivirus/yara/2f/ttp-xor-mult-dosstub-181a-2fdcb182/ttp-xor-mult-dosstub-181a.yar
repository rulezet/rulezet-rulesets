rule TTP_XOR_MULT_DOSStub_181a {
  strings:
    $key_181a = { 4c 72 [2] 38 6a [2] 7f 68 [2] 38 79 [2] 76 75 [2] 7a 7f [2] 6d 74 [2] 76 3a [2] 4b }

  condition:
    any of them
}