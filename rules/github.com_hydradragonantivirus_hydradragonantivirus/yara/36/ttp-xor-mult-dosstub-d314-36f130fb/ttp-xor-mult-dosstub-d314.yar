rule TTP_XOR_MULT_DOSStub_d314 {
  strings:
    $key_d314 = { 87 7c [2] f3 64 [2] b4 66 [2] f3 77 [2] bd 7b [2] b1 71 [2] a6 7a [2] bd 34 [2] 80 }

  condition:
    any of them
}