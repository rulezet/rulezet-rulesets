rule TTP_XOR_MULT_DOSStub_4865 {
  strings:
    $key_4865 = { 1c 0d [2] 68 15 [2] 2f 17 [2] 68 06 [2] 26 0a [2] 2a 00 [2] 3d 0b [2] 26 45 [2] 1b }

  condition:
    any of them
}