rule TTP_XOR_MULT_DOSStub_d303 {
  strings:
    $key_d303 = { 87 6b [2] f3 73 [2] b4 71 [2] f3 60 [2] bd 6c [2] b1 66 [2] a6 6d [2] bd 23 [2] 80 }

  condition:
    any of them
}