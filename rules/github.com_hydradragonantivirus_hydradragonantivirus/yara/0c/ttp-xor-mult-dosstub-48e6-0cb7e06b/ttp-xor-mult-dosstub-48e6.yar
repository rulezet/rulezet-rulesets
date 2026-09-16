rule TTP_XOR_MULT_DOSStub_48e6 {
  strings:
    $key_48e6 = { 1c 8e [2] 68 96 [2] 2f 94 [2] 68 85 [2] 26 89 [2] 2a 83 [2] 3d 88 [2] 26 c6 [2] 1b }

  condition:
    any of them
}