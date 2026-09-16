rule TTP_XOR_MULT_DOSStub_d319 {
  strings:
    $key_d319 = { 87 71 [2] f3 69 [2] b4 6b [2] f3 7a [2] bd 76 [2] b1 7c [2] a6 77 [2] bd 39 [2] 80 }

  condition:
    any of them
}