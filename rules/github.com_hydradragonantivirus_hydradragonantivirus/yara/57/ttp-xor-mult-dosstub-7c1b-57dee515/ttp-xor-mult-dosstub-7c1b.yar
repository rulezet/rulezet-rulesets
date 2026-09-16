rule TTP_XOR_MULT_DOSStub_7c1b {
  strings:
    $key_7c1b = { 28 73 [2] 5c 6b [2] 1b 69 [2] 5c 78 [2] 12 74 [2] 1e 7e [2] 09 75 [2] 12 3b [2] 2f }

  condition:
    any of them
}