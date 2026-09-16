rule TTP_XOR_MULT_DOSStub_4868 {
  strings:
    $key_4868 = { 1c 00 [2] 68 18 [2] 2f 1a [2] 68 0b [2] 26 07 [2] 2a 0d [2] 3d 06 [2] 26 48 [2] 1b }

  condition:
    any of them
}