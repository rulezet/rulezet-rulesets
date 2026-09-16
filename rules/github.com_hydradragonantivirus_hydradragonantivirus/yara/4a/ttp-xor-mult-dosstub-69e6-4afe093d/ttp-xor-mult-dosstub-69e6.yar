rule TTP_XOR_MULT_DOSStub_69e6 {
  strings:
    $key_69e6 = { 3d 8e [2] 49 96 [2] 0e 94 [2] 49 85 [2] 07 89 [2] 0b 83 [2] 1c 88 [2] 07 c6 [2] 3a }

  condition:
    any of them
}