rule TTP_XOR_MULT_DOSStub_6974 {
  strings:
    $key_6974 = { 3d 1c [2] 49 04 [2] 0e 06 [2] 49 17 [2] 07 1b [2] 0b 11 [2] 1c 1a [2] 07 54 [2] 3a }

  condition:
    any of them
}