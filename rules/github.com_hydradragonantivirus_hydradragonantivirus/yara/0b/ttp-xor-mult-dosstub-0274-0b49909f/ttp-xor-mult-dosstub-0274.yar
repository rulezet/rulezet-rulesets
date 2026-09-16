rule TTP_XOR_MULT_DOSStub_0274 {
  strings:
    $key_0274 = { 56 1c [2] 22 04 [2] 65 06 [2] 22 17 [2] 6c 1b [2] 60 11 [2] 77 1a [2] 6c 54 [2] 51 }

  condition:
    any of them
}