rule TTP_XOR_MULT_DOSStub_6e7d {
  strings:
    $key_6e7d = { 3a 15 [2] 4e 0d [2] 09 0f [2] 4e 1e [2] 00 12 [2] 0c 18 [2] 1b 13 [2] 00 5d [2] 3d }

  condition:
    any of them
}