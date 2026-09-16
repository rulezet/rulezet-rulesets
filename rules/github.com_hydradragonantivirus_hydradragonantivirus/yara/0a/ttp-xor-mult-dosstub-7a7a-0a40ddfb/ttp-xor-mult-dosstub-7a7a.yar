rule TTP_XOR_MULT_DOSStub_7a7a {
  strings:
    $key_7a7a = { 2e 12 [2] 5a 0a [2] 1d 08 [2] 5a 19 [2] 14 15 [2] 18 1f [2] 0f 14 [2] 14 5a [2] 29 }

  condition:
    any of them
}