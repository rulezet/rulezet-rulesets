rule TTP_XOR_MULT_DOSStub_337a {
  strings:
    $key_337a = { 67 12 [2] 13 0a [2] 54 08 [2] 13 19 [2] 5d 15 [2] 51 1f [2] 46 14 [2] 5d 5a [2] 60 }

  condition:
    any of them
}