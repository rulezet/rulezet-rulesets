rule TTP_XOR_MULT_DOSStub_69e9 {
  strings:
    $key_69e9 = { 3d 81 [2] 49 99 [2] 0e 9b [2] 49 8a [2] 07 86 [2] 0b 8c [2] 1c 87 [2] 07 c9 [2] 3a }

  condition:
    any of them
}