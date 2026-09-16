rule TTP_XOR_MULT_DOSStub_7c76 {
  strings:
    $key_7c76 = { 28 1e [2] 5c 06 [2] 1b 04 [2] 5c 15 [2] 12 19 [2] 1e 13 [2] 09 18 [2] 12 56 [2] 2f }

  condition:
    any of them
}