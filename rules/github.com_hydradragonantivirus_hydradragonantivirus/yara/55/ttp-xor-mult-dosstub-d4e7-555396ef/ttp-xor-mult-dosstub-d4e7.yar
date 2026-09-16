rule TTP_XOR_MULT_DOSStub_d4e7 {
  strings:
    $key_d4e7 = { 80 8f [2] f4 97 [2] b3 95 [2] f4 84 [2] ba 88 [2] b6 82 [2] a1 89 [2] ba c7 [2] 87 }

  condition:
    any of them
}