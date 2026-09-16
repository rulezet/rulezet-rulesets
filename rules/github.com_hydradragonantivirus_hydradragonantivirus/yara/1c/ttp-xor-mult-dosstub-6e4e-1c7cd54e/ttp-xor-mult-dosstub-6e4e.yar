rule TTP_XOR_MULT_DOSStub_6e4e {
  strings:
    $key_6e4e = { 3a 26 [2] 4e 3e [2] 09 3c [2] 4e 2d [2] 00 21 [2] 0c 2b [2] 1b 20 [2] 00 6e [2] 3d }

  condition:
    any of them
}