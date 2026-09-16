rule TTP_XOR_MULT_DOSStub_0a74 {
  strings:
    $key_0a74 = { 5e 1c [2] 2a 04 [2] 6d 06 [2] 2a 17 [2] 64 1b [2] 68 11 [2] 7f 1a [2] 64 54 [2] 59 }

  condition:
    any of them
}