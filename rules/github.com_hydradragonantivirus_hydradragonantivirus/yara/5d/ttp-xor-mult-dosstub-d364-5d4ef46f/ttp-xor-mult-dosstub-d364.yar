rule TTP_XOR_MULT_DOSStub_d364 {
  strings:
    $key_d364 = { 87 0c [2] f3 14 [2] b4 16 [2] f3 07 [2] bd 0b [2] b1 01 [2] a6 0a [2] bd 44 [2] 80 }

  condition:
    any of them
}