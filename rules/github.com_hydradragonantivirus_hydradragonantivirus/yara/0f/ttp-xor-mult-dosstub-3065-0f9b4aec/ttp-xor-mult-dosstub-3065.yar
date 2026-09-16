rule TTP_XOR_MULT_DOSStub_3065 {
  strings:
    $key_3065 = { 64 0d [2] 10 15 [2] 57 17 [2] 10 06 [2] 5e 0a [2] 52 00 [2] 45 0b [2] 5e 45 [2] 63 }

  condition:
    any of them
}