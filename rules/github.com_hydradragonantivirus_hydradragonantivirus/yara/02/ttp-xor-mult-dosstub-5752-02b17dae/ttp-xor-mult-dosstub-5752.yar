rule TTP_XOR_MULT_DOSStub_5752 {
  strings:
    $key_5752 = { 03 3a [2] 77 22 [2] 30 20 [2] 77 31 [2] 39 3d [2] 35 37 [2] 22 3c [2] 39 72 [2] 04 }

  condition:
    any of them
}