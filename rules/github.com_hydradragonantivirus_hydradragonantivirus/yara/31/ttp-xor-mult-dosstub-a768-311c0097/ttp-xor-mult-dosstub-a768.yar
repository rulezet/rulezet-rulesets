rule TTP_XOR_MULT_DOSStub_a768 {
  strings:
    $key_a768 = { f3 00 [2] 87 18 [2] c0 1a [2] 87 0b [2] c9 07 [2] c5 0d [2] d2 06 [2] c9 48 [2] f4 }

  condition:
    any of them
}