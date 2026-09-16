rule TTP_XOR_MULT_DOSStub_d325 {
  strings:
    $key_d325 = { 87 4d [2] f3 55 [2] b4 57 [2] f3 46 [2] bd 4a [2] b1 40 [2] a6 4b [2] bd 05 [2] 80 }

  condition:
    any of them
}