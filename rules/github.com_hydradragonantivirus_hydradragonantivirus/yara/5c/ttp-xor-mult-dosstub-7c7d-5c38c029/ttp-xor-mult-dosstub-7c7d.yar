rule TTP_XOR_MULT_DOSStub_7c7d {
  strings:
    $key_7c7d = { 28 15 [2] 5c 0d [2] 1b 0f [2] 5c 1e [2] 12 12 [2] 1e 18 [2] 09 13 [2] 12 5d [2] 2f }

  condition:
    any of them
}