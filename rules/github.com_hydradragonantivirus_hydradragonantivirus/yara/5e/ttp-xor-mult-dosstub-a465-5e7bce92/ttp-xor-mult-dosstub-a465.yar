rule TTP_XOR_MULT_DOSStub_a465 {
  strings:
    $key_a465 = { f0 0d [2] 84 15 [2] c3 17 [2] 84 06 [2] ca 0a [2] c6 00 [2] d1 0b [2] ca 45 [2] f7 }

  condition:
    any of them
}