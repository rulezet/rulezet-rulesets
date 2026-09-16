rule TTP_XOR_MULT_DOSStub_d408 {
  strings:
    $key_d408 = { 80 60 [2] f4 78 [2] b3 7a [2] f4 6b [2] ba 67 [2] b6 6d [2] a1 66 [2] ba 28 [2] 87 }

  condition:
    any of them
}