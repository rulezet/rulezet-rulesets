rule TTP_XOR_MULT_DOSStub_6e79 {
  strings:
    $key_6e79 = { 3a 11 [2] 4e 09 [2] 09 0b [2] 4e 1a [2] 00 16 [2] 0c 1c [2] 1b 17 [2] 00 59 [2] 3d }

  condition:
    any of them
}