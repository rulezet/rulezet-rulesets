rule TTP_XOR_MULT_DOSStub_d452 {
  strings:
    $key_d452 = { 80 3a [2] f4 22 [2] b3 20 [2] f4 31 [2] ba 3d [2] b6 37 [2] a1 3c [2] ba 72 [2] 87 }

  condition:
    any of them
}