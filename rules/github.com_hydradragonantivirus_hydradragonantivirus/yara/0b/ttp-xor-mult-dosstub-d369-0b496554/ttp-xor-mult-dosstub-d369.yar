rule TTP_XOR_MULT_DOSStub_d369 {
  strings:
    $key_d369 = { 87 01 [2] f3 19 [2] b4 1b [2] f3 0a [2] bd 06 [2] b1 0c [2] a6 07 [2] bd 49 [2] 80 }

  condition:
    any of them
}