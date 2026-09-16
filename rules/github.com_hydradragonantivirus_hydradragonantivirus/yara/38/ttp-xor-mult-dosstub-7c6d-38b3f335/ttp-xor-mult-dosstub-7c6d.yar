rule TTP_XOR_MULT_DOSStub_7c6d {
  strings:
    $key_7c6d = { 28 05 [2] 5c 1d [2] 1b 1f [2] 5c 0e [2] 12 02 [2] 1e 08 [2] 09 03 [2] 12 4d [2] 2f }

  condition:
    any of them
}