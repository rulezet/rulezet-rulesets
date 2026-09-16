rule TTP_XOR_MULT_DOSStub_4845 {
  strings:
    $key_4845 = { 1c 2d [2] 68 35 [2] 2f 37 [2] 68 26 [2] 26 2a [2] 2a 20 [2] 3d 2b [2] 26 65 [2] 1b }

  condition:
    any of them
}