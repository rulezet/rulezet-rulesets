rule TTP_XOR_MULT_DOSStub_d471 {
  strings:
    $key_d471 = { 80 19 [2] f4 01 [2] b3 03 [2] f4 12 [2] ba 1e [2] b6 14 [2] a1 1f [2] ba 51 [2] 87 }

  condition:
    any of them
}