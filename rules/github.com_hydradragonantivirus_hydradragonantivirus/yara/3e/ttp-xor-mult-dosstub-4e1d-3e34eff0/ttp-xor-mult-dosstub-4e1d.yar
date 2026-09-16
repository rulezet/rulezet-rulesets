rule TTP_XOR_MULT_DOSStub_4e1d {
  strings:
    $key_4e1d = { 1a 75 [2] 6e 6d [2] 29 6f [2] 6e 7e [2] 20 72 [2] 2c 78 [2] 3b 73 [2] 20 3d [2] 1d }

  condition:
    any of them
}