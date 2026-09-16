rule TTP_XOR_MULT_DOSStub_d415 {
  strings:
    $key_d415 = { 80 7d [2] f4 65 [2] b3 67 [2] f4 76 [2] ba 7a [2] b6 70 [2] a1 7b [2] ba 35 [2] 87 }

  condition:
    any of them
}