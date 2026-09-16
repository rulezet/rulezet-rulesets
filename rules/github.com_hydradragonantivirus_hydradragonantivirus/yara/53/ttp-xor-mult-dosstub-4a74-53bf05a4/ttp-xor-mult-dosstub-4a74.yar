rule TTP_XOR_MULT_DOSStub_4a74 {
  strings:
    $key_4a74 = { 1e 1c [2] 6a 04 [2] 2d 06 [2] 6a 17 [2] 24 1b [2] 28 11 [2] 3f 1a [2] 24 54 [2] 19 }

  condition:
    any of them
}