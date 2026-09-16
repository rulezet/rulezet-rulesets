rule TTP_XOR_MULT_DOSStub_4d64 {
  strings:
    $key_4d64 = { 19 0c [2] 6d 14 [2] 2a 16 [2] 6d 07 [2] 23 0b [2] 2f 01 [2] 38 0a [2] 23 44 [2] 1e }

  condition:
    any of them
}