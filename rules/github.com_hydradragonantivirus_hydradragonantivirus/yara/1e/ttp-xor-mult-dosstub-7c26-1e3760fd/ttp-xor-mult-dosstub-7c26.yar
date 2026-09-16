rule TTP_XOR_MULT_DOSStub_7c26 {
  strings:
    $key_7c26 = { 28 4e [2] 5c 56 [2] 1b 54 [2] 5c 45 [2] 12 49 [2] 1e 43 [2] 09 48 [2] 12 06 [2] 2f }

  condition:
    any of them
}