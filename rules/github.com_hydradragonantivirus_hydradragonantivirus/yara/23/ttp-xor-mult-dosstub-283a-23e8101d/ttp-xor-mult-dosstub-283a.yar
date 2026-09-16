rule TTP_XOR_MULT_DOSStub_283a {
  strings:
    $key_283a = { 7c 52 [2] 08 4a [2] 4f 48 [2] 08 59 [2] 46 55 [2] 4a 5f [2] 5d 54 [2] 46 1a [2] 7b }

  condition:
    any of them
}