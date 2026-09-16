rule TTP_XOR_MULT_DOSStub_6e63 {
  strings:
    $key_6e63 = { 3a 0b [2] 4e 13 [2] 09 11 [2] 4e 00 [2] 00 0c [2] 0c 06 [2] 1b 0d [2] 00 43 [2] 3d }

  condition:
    any of them
}