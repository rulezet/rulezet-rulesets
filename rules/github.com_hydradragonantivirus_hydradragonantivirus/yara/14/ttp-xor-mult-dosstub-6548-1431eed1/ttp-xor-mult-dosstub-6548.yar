rule TTP_XOR_MULT_DOSStub_6548 {
  strings:
    $key_6548 = { 31 20 [2] 45 38 [2] 02 3a [2] 45 2b [2] 0b 27 [2] 07 2d [2] 10 26 [2] 0b 68 [2] 36 }

  condition:
    any of them
}