rule TTP_XOR_MULT_DOSStub_d412 {
  strings:
    $key_d412 = { 80 7a [2] f4 62 [2] b3 60 [2] f4 71 [2] ba 7d [2] b6 77 [2] a1 7c [2] ba 32 [2] 87 }

  condition:
    any of them
}