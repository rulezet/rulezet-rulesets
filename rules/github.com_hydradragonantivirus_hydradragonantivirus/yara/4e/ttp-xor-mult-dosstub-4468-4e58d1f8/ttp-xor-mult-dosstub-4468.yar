rule TTP_XOR_MULT_DOSStub_4468 {
  strings:
    $key_4468 = { 10 00 [2] 64 18 [2] 23 1a [2] 64 0b [2] 2a 07 [2] 26 0d [2] 31 06 [2] 2a 48 [2] 17 }

  condition:
    any of them
}