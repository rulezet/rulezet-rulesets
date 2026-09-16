rule TTP_XOR_MULT_DOSStub_3a0a {
  strings:
    $key_3a0a = { 6e 62 [2] 1a 7a [2] 5d 78 [2] 1a 69 [2] 54 65 [2] 58 6f [2] 4f 64 [2] 54 2a [2] 69 }

  condition:
    any of them
}