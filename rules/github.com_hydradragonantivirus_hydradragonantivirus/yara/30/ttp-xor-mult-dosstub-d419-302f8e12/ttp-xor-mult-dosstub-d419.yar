rule TTP_XOR_MULT_DOSStub_d419 {
  strings:
    $key_d419 = { 80 71 [2] f4 69 [2] b3 6b [2] f4 7a [2] ba 76 [2] b6 7c [2] a1 77 [2] ba 39 [2] 87 }

  condition:
    any of them
}