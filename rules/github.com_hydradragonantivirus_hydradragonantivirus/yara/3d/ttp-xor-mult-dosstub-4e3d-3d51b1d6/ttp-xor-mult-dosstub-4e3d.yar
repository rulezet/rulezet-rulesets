rule TTP_XOR_MULT_DOSStub_4e3d {
  strings:
    $key_4e3d = { 1a 55 [2] 6e 4d [2] 29 4f [2] 6e 5e [2] 20 52 [2] 2c 58 [2] 3b 53 [2] 20 1d [2] 1d }

  condition:
    any of them
}