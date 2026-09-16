rule TTP_XOR_MULT_DOSStub_766a {
  strings:
    $key_766a = { 22 02 [2] 56 1a [2] 11 18 [2] 56 09 [2] 18 05 [2] 14 0f [2] 03 04 [2] 18 4a [2] 25 }

  condition:
    any of them
}