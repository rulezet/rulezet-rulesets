rule TTP_XOR_MULT_DOSStub_4c7b {
  strings:
    $key_4c7b = { 18 13 [2] 6c 0b [2] 2b 09 [2] 6c 18 [2] 22 14 [2] 2e 1e [2] 39 15 [2] 22 5b [2] 1f }

  condition:
    any of them
}