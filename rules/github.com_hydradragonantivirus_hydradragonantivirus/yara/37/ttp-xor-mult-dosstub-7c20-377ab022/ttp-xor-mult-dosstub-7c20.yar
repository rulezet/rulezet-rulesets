rule TTP_XOR_MULT_DOSStub_7c20 {
  strings:
    $key_7c20 = { 28 48 [2] 5c 50 [2] 1b 52 [2] 5c 43 [2] 12 4f [2] 1e 45 [2] 09 4e [2] 12 00 [2] 2f }

  condition:
    any of them
}