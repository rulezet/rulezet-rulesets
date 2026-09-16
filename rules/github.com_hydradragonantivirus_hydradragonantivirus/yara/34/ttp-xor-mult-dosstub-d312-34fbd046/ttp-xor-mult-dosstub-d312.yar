rule TTP_XOR_MULT_DOSStub_d312 {
  strings:
    $key_d312 = { 87 7a [2] f3 62 [2] b4 60 [2] f3 71 [2] bd 7d [2] b1 77 [2] a6 7c [2] bd 32 [2] 80 }

  condition:
    any of them
}