rule TTP_XOR_MULT_DOSStub_3a74 {
  strings:
    $key_3a74 = { 6e 1c [2] 1a 04 [2] 5d 06 [2] 1a 17 [2] 54 1b [2] 58 11 [2] 4f 1a [2] 54 54 [2] 69 }

  condition:
    any of them
}