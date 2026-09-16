rule TTP_XOR_MULT_DOSStub_7c61 {
  strings:
    $key_7c61 = { 28 09 [2] 5c 11 [2] 1b 13 [2] 5c 02 [2] 12 0e [2] 1e 04 [2] 09 0f [2] 12 41 [2] 2f }

  condition:
    any of them
}