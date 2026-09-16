rule TTP_XOR_MULT_DOSStub_5d0a {
  strings:
    $key_5d0a = { 09 62 [2] 7d 7a [2] 3a 78 [2] 7d 69 [2] 33 65 [2] 3f 6f [2] 28 64 [2] 33 2a [2] 0e }

  condition:
    any of them
}