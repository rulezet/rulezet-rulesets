rule TTP_XOR_MULT_DOSStub_6e65 {
  strings:
    $key_6e65 = { 3a 0d [2] 4e 15 [2] 09 17 [2] 4e 06 [2] 00 0a [2] 0c 00 [2] 1b 0b [2] 00 45 [2] 3d }

  condition:
    any of them
}