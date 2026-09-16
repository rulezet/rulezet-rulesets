rule TTP_XOR_MULT_DOSStub_d475 {
  strings:
    $key_d475 = { 80 1d [2] f4 05 [2] b3 07 [2] f4 16 [2] ba 1a [2] b6 10 [2] a1 1b [2] ba 55 [2] 87 }

  condition:
    any of them
}