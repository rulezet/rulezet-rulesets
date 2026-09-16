rule TTP_XOR_MULT_DOSStub_6e47 {
  strings:
    $key_6e47 = { 3a 2f [2] 4e 37 [2] 09 35 [2] 4e 24 [2] 00 28 [2] 0c 22 [2] 1b 29 [2] 00 67 [2] 3d }

  condition:
    any of them
}