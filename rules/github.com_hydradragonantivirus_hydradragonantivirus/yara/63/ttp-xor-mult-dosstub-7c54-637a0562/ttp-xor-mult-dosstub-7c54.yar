rule TTP_XOR_MULT_DOSStub_7c54 {
  strings:
    $key_7c54 = { 28 3c [2] 5c 24 [2] 1b 26 [2] 5c 37 [2] 12 3b [2] 1e 31 [2] 09 3a [2] 12 74 [2] 2f }

  condition:
    any of them
}