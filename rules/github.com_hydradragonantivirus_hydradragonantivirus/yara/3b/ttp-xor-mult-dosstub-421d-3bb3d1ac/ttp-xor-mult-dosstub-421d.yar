rule TTP_XOR_MULT_DOSStub_421d {
  strings:
    $key_421d = { 16 75 [2] 62 6d [2] 25 6f [2] 62 7e [2] 2c 72 [2] 20 78 [2] 37 73 [2] 2c 3d [2] 11 }

  condition:
    any of them
}