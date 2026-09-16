rule TTP_XOR_MULT_DOSStub_0e7b {
  strings:
    $key_0e7b = { 5a 13 [2] 2e 0b [2] 69 09 [2] 2e 18 [2] 60 14 [2] 6c 1e [2] 7b 15 [2] 60 5b [2] 5d }

  condition:
    any of them
}