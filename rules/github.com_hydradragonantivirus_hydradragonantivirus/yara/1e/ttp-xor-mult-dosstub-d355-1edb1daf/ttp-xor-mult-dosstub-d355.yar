rule TTP_XOR_MULT_DOSStub_d355 {
  strings:
    $key_d355 = { 87 3d [2] f3 25 [2] b4 27 [2] f3 36 [2] bd 3a [2] b1 30 [2] a6 3b [2] bd 75 [2] 80 }

  condition:
    any of them
}