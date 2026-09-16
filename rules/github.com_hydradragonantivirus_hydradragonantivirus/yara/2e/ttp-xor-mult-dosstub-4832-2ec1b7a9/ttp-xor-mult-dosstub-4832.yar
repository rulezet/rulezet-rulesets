rule TTP_XOR_MULT_DOSStub_4832 {
  strings:
    $key_4832 = { 1c 5a [2] 68 42 [2] 2f 40 [2] 68 51 [2] 26 5d [2] 2a 57 [2] 3d 5c [2] 26 12 [2] 1b }

  condition:
    any of them
}