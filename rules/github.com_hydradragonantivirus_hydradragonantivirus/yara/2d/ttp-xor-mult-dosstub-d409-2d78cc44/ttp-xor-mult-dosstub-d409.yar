rule TTP_XOR_MULT_DOSStub_d409 {
  strings:
    $key_d409 = { 80 61 [2] f4 79 [2] b3 7b [2] f4 6a [2] ba 66 [2] b6 6c [2] a1 67 [2] ba 29 [2] 87 }

  condition:
    any of them
}