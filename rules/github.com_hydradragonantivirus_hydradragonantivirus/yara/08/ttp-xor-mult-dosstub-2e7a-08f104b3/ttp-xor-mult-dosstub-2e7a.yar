rule TTP_XOR_MULT_DOSStub_2e7a {
  strings:
    $key_2e7a = { 7a 12 [2] 0e 0a [2] 49 08 [2] 0e 19 [2] 40 15 [2] 4c 1f [2] 5b 14 [2] 40 5a [2] 7d }

  condition:
    any of them
}