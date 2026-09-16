rule TTP_XOR_MULT_DOSStub_317a {
  strings:
    $key_317a = { 65 12 [2] 11 0a [2] 56 08 [2] 11 19 [2] 5f 15 [2] 53 1f [2] 44 14 [2] 5f 5a [2] 62 }

  condition:
    any of them
}