rule TTP_XOR_MULT_DOSStub_4875 {
  strings:
    $key_4875 = { 1c 1d [2] 68 05 [2] 2f 07 [2] 68 16 [2] 26 1a [2] 2a 10 [2] 3d 1b [2] 26 55 [2] 1b }

  condition:
    any of them
}