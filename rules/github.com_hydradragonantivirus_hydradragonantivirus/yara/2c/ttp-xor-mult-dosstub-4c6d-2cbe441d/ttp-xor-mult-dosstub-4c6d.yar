rule TTP_XOR_MULT_DOSStub_4c6d {
  strings:
    $key_4c6d = { 18 05 [2] 6c 1d [2] 2b 1f [2] 6c 0e [2] 22 02 [2] 2e 08 [2] 39 03 [2] 22 4d [2] 1f }

  condition:
    any of them
}