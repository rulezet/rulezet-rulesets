rule TTP_XOR_MULT_DOSStub_6919 {
  strings:
    $key_6919 = { 3d 71 [2] 49 69 [2] 0e 6b [2] 49 7a [2] 07 76 [2] 0b 7c [2] 1c 77 [2] 07 39 [2] 3a }

  condition:
    any of them
}