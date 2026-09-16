rule TTP_XOR_MULT_DOSStub_8365 {
  strings:
    $key_8365 = { d7 0d [2] a3 15 [2] e4 17 [2] a3 06 [2] ed 0a [2] e1 00 [2] f6 0b [2] ed 45 [2] d0 }

  condition:
    any of them
}