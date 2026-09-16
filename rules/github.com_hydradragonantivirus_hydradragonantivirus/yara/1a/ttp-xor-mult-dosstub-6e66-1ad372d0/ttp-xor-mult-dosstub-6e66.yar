rule TTP_XOR_MULT_DOSStub_6e66 {
  strings:
    $key_6e66 = { 3a 0e [2] 4e 16 [2] 09 14 [2] 4e 05 [2] 00 09 [2] 0c 03 [2] 1b 08 [2] 00 46 [2] 3d }

  condition:
    any of them
}