rule TTP_XOR_MULT_DOSStub_4842 {
  strings:
    $key_4842 = { 1c 2a [2] 68 32 [2] 2f 30 [2] 68 21 [2] 26 2d [2] 2a 27 [2] 3d 2c [2] 26 62 [2] 1b }

  condition:
    any of them
}