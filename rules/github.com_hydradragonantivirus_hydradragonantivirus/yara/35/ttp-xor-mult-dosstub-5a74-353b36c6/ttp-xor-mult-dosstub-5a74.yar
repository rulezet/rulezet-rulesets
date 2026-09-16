rule TTP_XOR_MULT_DOSStub_5a74 {
  strings:
    $key_5a74 = { 0e 1c [2] 7a 04 [2] 3d 06 [2] 7a 17 [2] 34 1b [2] 38 11 [2] 2f 1a [2] 34 54 [2] 09 }

  condition:
    any of them
}