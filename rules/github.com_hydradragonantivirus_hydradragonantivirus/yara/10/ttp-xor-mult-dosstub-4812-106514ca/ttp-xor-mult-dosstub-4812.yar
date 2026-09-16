rule TTP_XOR_MULT_DOSStub_4812 {
  strings:
    $key_4812 = { 1c 7a [2] 68 62 [2] 2f 60 [2] 68 71 [2] 26 7d [2] 2a 77 [2] 3d 7c [2] 26 32 [2] 1b }

  condition:
    any of them
}