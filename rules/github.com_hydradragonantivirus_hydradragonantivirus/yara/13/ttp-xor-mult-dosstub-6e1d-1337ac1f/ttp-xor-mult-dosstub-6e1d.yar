rule TTP_XOR_MULT_DOSStub_6e1d {
  strings:
    $key_6e1d = { 3a 75 [2] 4e 6d [2] 09 6f [2] 4e 7e [2] 00 72 [2] 0c 78 [2] 1b 73 [2] 00 3d [2] 3d }

  condition:
    any of them
}