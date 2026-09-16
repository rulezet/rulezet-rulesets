rule TTP_XOR_MULT_DOSStub_6ee6 {
  strings:
    $key_6ee6 = { 3a 8e [2] 4e 96 [2] 09 94 [2] 4e 85 [2] 00 89 [2] 0c 83 [2] 1b 88 [2] 00 c6 [2] 3d }

  condition:
    any of them
}