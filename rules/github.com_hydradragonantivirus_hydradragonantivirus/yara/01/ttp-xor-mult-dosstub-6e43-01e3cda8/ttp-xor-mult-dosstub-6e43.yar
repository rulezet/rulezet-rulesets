rule TTP_XOR_MULT_DOSStub_6e43 {
  strings:
    $key_6e43 = { 3a 2b [2] 4e 33 [2] 09 31 [2] 4e 20 [2] 00 2c [2] 0c 26 [2] 1b 2d [2] 00 63 [2] 3d }

  condition:
    any of them
}