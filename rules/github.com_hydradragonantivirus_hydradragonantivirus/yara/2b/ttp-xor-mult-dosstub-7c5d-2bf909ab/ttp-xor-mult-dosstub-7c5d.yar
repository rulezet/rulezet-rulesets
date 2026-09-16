rule TTP_XOR_MULT_DOSStub_7c5d {
  strings:
    $key_7c5d = { 28 35 [2] 5c 2d [2] 1b 2f [2] 5c 3e [2] 12 32 [2] 1e 38 [2] 09 33 [2] 12 7d [2] 2f }

  condition:
    any of them
}