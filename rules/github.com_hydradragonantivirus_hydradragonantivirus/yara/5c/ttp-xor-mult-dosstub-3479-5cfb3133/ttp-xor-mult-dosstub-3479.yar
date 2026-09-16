rule TTP_XOR_MULT_DOSStub_3479 {
  strings:
    $key_3479 = { 60 11 [2] 14 09 [2] 53 0b [2] 14 1a [2] 5a 16 [2] 56 1c [2] 41 17 [2] 5a 59 [2] 67 }

  condition:
    any of them
}