rule TTP_XOR_MULT_DOSStub_d368 {
  strings:
    $key_d368 = { 87 00 [2] f3 18 [2] b4 1a [2] f3 0b [2] bd 07 [2] b1 0d [2] a6 06 [2] bd 48 [2] 80 }

  condition:
    any of them
}