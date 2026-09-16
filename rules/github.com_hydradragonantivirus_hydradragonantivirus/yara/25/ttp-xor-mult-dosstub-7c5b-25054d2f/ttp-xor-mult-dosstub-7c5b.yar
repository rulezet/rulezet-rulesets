rule TTP_XOR_MULT_DOSStub_7c5b {
  strings:
    $key_7c5b = { 28 33 [2] 5c 2b [2] 1b 29 [2] 5c 38 [2] 12 34 [2] 1e 3e [2] 09 35 [2] 12 7b [2] 2f }

  condition:
    any of them
}