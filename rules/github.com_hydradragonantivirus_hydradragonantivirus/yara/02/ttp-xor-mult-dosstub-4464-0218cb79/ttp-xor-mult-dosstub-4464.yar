rule TTP_XOR_MULT_DOSStub_4464 {
  strings:
    $key_4464 = { 10 0c [2] 64 14 [2] 23 16 [2] 64 07 [2] 2a 0b [2] 26 01 [2] 31 0a [2] 2a 44 [2] 17 }

  condition:
    any of them
}