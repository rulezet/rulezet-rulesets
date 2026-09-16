rule TTP_XOR_MULT_DOSStub_d432 {
  strings:
    $key_d432 = { 80 5a [2] f4 42 [2] b3 40 [2] f4 51 [2] ba 5d [2] b6 57 [2] a1 5c [2] ba 12 [2] 87 }

  condition:
    any of them
}