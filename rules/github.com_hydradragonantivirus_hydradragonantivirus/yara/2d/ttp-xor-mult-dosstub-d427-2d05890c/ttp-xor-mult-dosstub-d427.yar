rule TTP_XOR_MULT_DOSStub_d427 {
  strings:
    $key_d427 = { 80 4f [2] f4 57 [2] b3 55 [2] f4 44 [2] ba 48 [2] b6 42 [2] a1 49 [2] ba 07 [2] 87 }

  condition:
    any of them
}