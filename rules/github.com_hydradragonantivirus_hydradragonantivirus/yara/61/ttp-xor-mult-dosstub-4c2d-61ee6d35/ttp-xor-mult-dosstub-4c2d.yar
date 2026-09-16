rule TTP_XOR_MULT_DOSStub_4c2d {
  strings:
    $key_4c2d = { 18 45 [2] 6c 5d [2] 2b 5f [2] 6c 4e [2] 22 42 [2] 2e 48 [2] 39 43 [2] 22 0d [2] 1f }

  condition:
    any of them
}