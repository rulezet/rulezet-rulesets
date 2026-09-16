rule TTP_XOR_MULT_DOSStub_6e14 {
  strings:
    $key_6e14 = { 3a 7c [2] 4e 64 [2] 09 66 [2] 4e 77 [2] 00 7b [2] 0c 71 [2] 1b 7a [2] 00 34 [2] 3d }

  condition:
    any of them
}