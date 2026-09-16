rule TTP_XOR_MULT_DOSStub_6e72 {
  strings:
    $key_6e72 = { 3a 1a [2] 4e 02 [2] 09 00 [2] 4e 11 [2] 00 1d [2] 0c 17 [2] 1b 1c [2] 00 52 [2] 3d }

  condition:
    any of them
}