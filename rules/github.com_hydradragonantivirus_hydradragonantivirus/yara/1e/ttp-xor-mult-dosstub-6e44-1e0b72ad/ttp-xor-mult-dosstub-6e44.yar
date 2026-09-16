rule TTP_XOR_MULT_DOSStub_6e44 {
  strings:
    $key_6e44 = { 3a 2c [2] 4e 34 [2] 09 36 [2] 4e 27 [2] 00 2b [2] 0c 21 [2] 1b 2a [2] 00 64 [2] 3d }

  condition:
    any of them
}