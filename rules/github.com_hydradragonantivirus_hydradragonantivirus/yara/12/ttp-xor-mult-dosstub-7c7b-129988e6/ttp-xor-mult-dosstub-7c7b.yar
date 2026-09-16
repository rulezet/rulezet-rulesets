rule TTP_XOR_MULT_DOSStub_7c7b {
  strings:
    $key_7c7b = { 28 13 [2] 5c 0b [2] 1b 09 [2] 5c 18 [2] 12 14 [2] 1e 1e [2] 09 15 [2] 12 5b [2] 2f }

  condition:
    any of them
}