rule TTP_XOR_MULT_DOSStub_6ee4 {
  strings:
    $key_6ee4 = { 3a 8c [2] 4e 94 [2] 09 96 [2] 4e 87 [2] 00 8b [2] 0c 81 [2] 1b 8a [2] 00 c4 [2] 3d }

  condition:
    any of them
}