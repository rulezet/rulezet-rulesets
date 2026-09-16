rule TTP_XOR_MULT_DOSStub_4872 {
  strings:
    $key_4872 = { 1c 1a [2] 68 02 [2] 2f 00 [2] 68 11 [2] 26 1d [2] 2a 17 [2] 3d 1c [2] 26 52 [2] 1b }

  condition:
    any of them
}