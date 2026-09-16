rule TTP_XOR_MULT_DOSStub_2a74 {
  strings:
    $key_2a74 = { 7e 1c [2] 0a 04 [2] 4d 06 [2] 0a 17 [2] 44 1b [2] 48 11 [2] 5f 1a [2] 44 54 [2] 79 }

  condition:
    any of them
}