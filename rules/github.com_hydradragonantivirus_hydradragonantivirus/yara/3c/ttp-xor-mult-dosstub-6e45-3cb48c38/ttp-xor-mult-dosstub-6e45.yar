rule TTP_XOR_MULT_DOSStub_6e45 {
  strings:
    $key_6e45 = { 3a 2d [2] 4e 35 [2] 09 37 [2] 4e 26 [2] 00 2a [2] 0c 20 [2] 1b 2b [2] 00 65 [2] 3d }

  condition:
    any of them
}