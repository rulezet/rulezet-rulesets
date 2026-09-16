rule TTP_XOR_MULT_DOSStub_d363 {
  strings:
    $key_d363 = { 87 0b [2] f3 13 [2] b4 11 [2] f3 00 [2] bd 0c [2] b1 06 [2] a6 0d [2] bd 43 [2] 80 }

  condition:
    any of them
}