rule TTP_XOR_MULT_DOSStub_3465 {
  strings:
    $key_3465 = { 60 0d [2] 14 15 [2] 53 17 [2] 14 06 [2] 5a 0a [2] 56 00 [2] 41 0b [2] 5a 45 [2] 67 }

  condition:
    any of them
}