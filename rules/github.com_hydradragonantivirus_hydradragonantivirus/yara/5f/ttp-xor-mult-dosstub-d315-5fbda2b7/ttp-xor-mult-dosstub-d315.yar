rule TTP_XOR_MULT_DOSStub_d315 {
  strings:
    $key_d315 = { 87 7d [2] f3 65 [2] b4 67 [2] f3 76 [2] bd 7a [2] b1 70 [2] a6 7b [2] bd 35 [2] 80 }

  condition:
    any of them
}