rule TTP_XOR_MULT_DOSStub_7c41 {
  strings:
    $key_7c41 = { 28 29 [2] 5c 31 [2] 1b 33 [2] 5c 22 [2] 12 2e [2] 1e 24 [2] 09 2f [2] 12 61 [2] 2f }

  condition:
    any of them
}