rule TTP_XOR_MULT_DOSStub_6e49 {
  strings:
    $key_6e49 = { 3a 21 [2] 4e 39 [2] 09 3b [2] 4e 2a [2] 00 26 [2] 0c 2c [2] 1b 27 [2] 00 69 [2] 3d }

  condition:
    any of them
}