rule TTP_XOR_MULT_DOSStub_4838 {
  strings:
    $key_4838 = { 1c 50 [2] 68 48 [2] 2f 4a [2] 68 5b [2] 26 57 [2] 2a 5d [2] 3d 56 [2] 26 18 [2] 1b }

  condition:
    any of them
}