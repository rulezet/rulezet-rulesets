rule TTP_XOR_MULT_DOSStub_6e56 {
  strings:
    $key_6e56 = { 3a 3e [2] 4e 26 [2] 09 24 [2] 4e 35 [2] 00 39 [2] 0c 33 [2] 1b 38 [2] 00 76 [2] 3d }

  condition:
    any of them
}