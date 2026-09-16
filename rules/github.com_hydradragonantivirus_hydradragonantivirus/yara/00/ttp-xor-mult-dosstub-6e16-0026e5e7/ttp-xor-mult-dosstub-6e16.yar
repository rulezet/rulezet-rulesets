rule TTP_XOR_MULT_DOSStub_6e16 {
  strings:
    $key_6e16 = { 3a 7e [2] 4e 66 [2] 09 64 [2] 4e 75 [2] 00 79 [2] 0c 73 [2] 1b 78 [2] 00 36 [2] 3d }

  condition:
    any of them
}