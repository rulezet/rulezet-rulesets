rule TTP_XOR_MULT_DOSStub_3768 {
  strings:
    $key_3768 = { 63 00 [2] 17 18 [2] 50 1a [2] 17 0b [2] 59 07 [2] 55 0d [2] 42 06 [2] 59 48 [2] 64 }

  condition:
    any of them
}