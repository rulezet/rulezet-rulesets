rule TTP_XOR_MULT_DOSStub_2e4d {
  strings:
    $key_2e4d = { 7a 25 [2] 0e 3d [2] 49 3f [2] 0e 2e [2] 40 22 [2] 4c 28 [2] 5b 23 [2] 40 6d [2] 7d }

  condition:
    any of them
}