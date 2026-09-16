rule TTP_XOR_MULT_DOSStub_0e7a {
  strings:
    $key_0e7a = { 5a 12 [2] 2e 0a [2] 69 08 [2] 2e 19 [2] 60 15 [2] 6c 1f [2] 7b 14 [2] 60 5a [2] 5d }

  condition:
    any of them
}