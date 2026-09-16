rule TTP_XOR_MULT_DOSStub_7c6b {
  strings:
    $key_7c6b = { 28 03 [2] 5c 1b [2] 1b 19 [2] 5c 08 [2] 12 04 [2] 1e 0e [2] 09 05 [2] 12 4b [2] 2f }

  condition:
    any of them
}