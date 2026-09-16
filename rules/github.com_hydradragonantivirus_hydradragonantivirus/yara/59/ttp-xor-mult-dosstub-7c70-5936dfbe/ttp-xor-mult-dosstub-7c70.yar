rule TTP_XOR_MULT_DOSStub_7c70 {
  strings:
    $key_7c70 = { 28 18 [2] 5c 00 [2] 1b 02 [2] 5c 13 [2] 12 1f [2] 1e 15 [2] 09 1e [2] 12 50 [2] 2f }

  condition:
    any of them
}