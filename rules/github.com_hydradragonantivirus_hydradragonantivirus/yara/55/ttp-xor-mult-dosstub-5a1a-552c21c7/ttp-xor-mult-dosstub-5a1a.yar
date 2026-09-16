rule TTP_XOR_MULT_DOSStub_5a1a {
  strings:
    $key_5a1a = { 0e 72 [2] 7a 6a [2] 3d 68 [2] 7a 79 [2] 34 75 [2] 38 7f [2] 2f 74 [2] 34 3a [2] 09 }

  condition:
    any of them
}