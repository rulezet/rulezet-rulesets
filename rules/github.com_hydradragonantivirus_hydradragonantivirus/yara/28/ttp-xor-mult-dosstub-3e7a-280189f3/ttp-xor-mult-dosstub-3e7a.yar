rule TTP_XOR_MULT_DOSStub_3e7a {
  strings:
    $key_3e7a = { 6a 12 [2] 1e 0a [2] 59 08 [2] 1e 19 [2] 50 15 [2] 5c 1f [2] 4b 14 [2] 50 5a [2] 6d }

  condition:
    any of them
}