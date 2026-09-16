rule TTP_XOR_MULT_DOSStub_d309 {
  strings:
    $key_d309 = { 87 61 [2] f3 79 [2] b4 7b [2] f3 6a [2] bd 66 [2] b1 6c [2] a6 67 [2] bd 29 [2] 80 }

  condition:
    any of them
}