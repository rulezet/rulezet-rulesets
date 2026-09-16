rule TTP_XOR_MULT_DOSStub_4864 {
  strings:
    $key_4864 = { 1c 0c [2] 68 14 [2] 2f 16 [2] 68 07 [2] 26 0b [2] 2a 01 [2] 3d 0a [2] 26 44 [2] 1b }

  condition:
    any of them
}