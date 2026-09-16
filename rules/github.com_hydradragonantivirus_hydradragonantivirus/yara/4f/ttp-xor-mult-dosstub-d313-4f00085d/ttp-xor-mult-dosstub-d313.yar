rule TTP_XOR_MULT_DOSStub_d313 {
  strings:
    $key_d313 = { 87 7b [2] f3 63 [2] b4 61 [2] f3 70 [2] bd 7c [2] b1 76 [2] a6 7d [2] bd 33 [2] 80 }

  condition:
    any of them
}