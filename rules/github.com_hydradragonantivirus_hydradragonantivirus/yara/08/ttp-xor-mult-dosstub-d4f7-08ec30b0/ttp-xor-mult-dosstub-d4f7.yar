rule TTP_XOR_MULT_DOSStub_d4f7 {
  strings:
    $key_d4f7 = { 80 9f [2] f4 87 [2] b3 85 [2] f4 94 [2] ba 98 [2] b6 92 [2] a1 99 [2] ba d7 [2] 87 }

  condition:
    any of them
}