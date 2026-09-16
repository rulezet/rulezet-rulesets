rule TTP_XOR_MULT_DOSStub_7c65 {
  strings:
    $key_7c65 = { 28 0d [2] 5c 15 [2] 1b 17 [2] 5c 06 [2] 12 0a [2] 1e 00 [2] 09 0b [2] 12 45 [2] 2f }

  condition:
    any of them
}