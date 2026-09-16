rule TTP_XOR_MULT_DOSStub_6e48 {
  strings:
    $key_6e48 = { 3a 20 [2] 4e 38 [2] 09 3a [2] 4e 2b [2] 00 27 [2] 0c 2d [2] 1b 26 [2] 00 68 [2] 3d }

  condition:
    any of them
}