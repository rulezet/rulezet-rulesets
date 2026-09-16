rule TTP_XOR_MULT_DOSStub_747a {
  strings:
    $key_747a = { 20 12 [2] 54 0a [2] 13 08 [2] 54 19 [2] 1a 15 [2] 16 1f [2] 01 14 [2] 1a 5a [2] 27 }

  condition:
    any of them
}