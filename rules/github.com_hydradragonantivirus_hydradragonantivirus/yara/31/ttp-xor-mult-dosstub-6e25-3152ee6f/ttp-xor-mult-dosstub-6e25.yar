rule TTP_XOR_MULT_DOSStub_6e25 {
  strings:
    $key_6e25 = { 3a 4d [2] 4e 55 [2] 09 57 [2] 4e 46 [2] 00 4a [2] 0c 40 [2] 1b 4b [2] 00 05 [2] 3d }

  condition:
    any of them
}