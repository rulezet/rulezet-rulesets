rule TTP_XOR_MULT_DOSStub_4c5d {
  strings:
    $key_4c5d = { 18 35 [2] 6c 2d [2] 2b 2f [2] 6c 3e [2] 22 32 [2] 2e 38 [2] 39 33 [2] 22 7d [2] 1f }

  condition:
    any of them
}