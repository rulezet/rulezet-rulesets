rule TTP_XOR_MULT_DOSStub_6e4d {
  strings:
    $key_6e4d = { 3a 25 [2] 4e 3d [2] 09 3f [2] 4e 2e [2] 00 22 [2] 0c 28 [2] 1b 23 [2] 00 6d [2] 3d }

  condition:
    any of them
}