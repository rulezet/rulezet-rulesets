rule TTP_XOR_MULT_DOSStub_037a {
  strings:
    $key_037a = { 57 12 [2] 23 0a [2] 64 08 [2] 23 19 [2] 6d 15 [2] 61 1f [2] 76 14 [2] 6d 5a [2] 50 }

  condition:
    any of them
}