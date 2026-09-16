rule TTP_XOR_MULT_DOSStub_3765 {
  strings:
    $key_3765 = { 63 0d [2] 17 15 [2] 50 17 [2] 17 06 [2] 59 0a [2] 55 00 [2] 42 0b [2] 59 45 [2] 64 }

  condition:
    any of them
}