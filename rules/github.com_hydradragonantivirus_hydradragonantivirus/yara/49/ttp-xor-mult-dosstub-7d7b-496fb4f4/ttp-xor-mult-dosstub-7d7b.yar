rule TTP_XOR_MULT_DOSStub_7d7b {
  strings:
    $key_7d7b = { 29 13 [2] 5d 0b [2] 1a 09 [2] 5d 18 [2] 13 14 [2] 1f 1e [2] 08 15 [2] 13 5b [2] 2e }

  condition:
    any of them
}