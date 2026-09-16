rule TTP_XOR_MULT_DOSStub_7ce5 {
  strings:
    $key_7ce5 = { 28 8d [2] 5c 95 [2] 1b 97 [2] 5c 86 [2] 12 8a [2] 1e 80 [2] 09 8b [2] 12 c5 [2] 2f }

  condition:
    any of them
}