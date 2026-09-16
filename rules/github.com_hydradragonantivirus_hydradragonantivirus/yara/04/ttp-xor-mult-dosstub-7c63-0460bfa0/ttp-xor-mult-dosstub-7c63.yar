rule TTP_XOR_MULT_DOSStub_7c63 {
  strings:
    $key_7c63 = { 28 0b [2] 5c 13 [2] 1b 11 [2] 5c 00 [2] 12 0c [2] 1e 06 [2] 09 0d [2] 12 43 [2] 2f }

  condition:
    any of them
}