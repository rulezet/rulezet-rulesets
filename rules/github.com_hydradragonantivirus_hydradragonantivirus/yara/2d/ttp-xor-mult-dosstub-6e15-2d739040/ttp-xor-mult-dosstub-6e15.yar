rule TTP_XOR_MULT_DOSStub_6e15 {
  strings:
    $key_6e15 = { 3a 7d [2] 4e 65 [2] 09 67 [2] 4e 76 [2] 00 7a [2] 0c 70 [2] 1b 7b [2] 00 35 [2] 3d }

  condition:
    any of them
}