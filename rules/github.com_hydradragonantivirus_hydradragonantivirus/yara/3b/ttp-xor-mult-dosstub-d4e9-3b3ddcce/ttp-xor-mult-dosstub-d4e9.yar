rule TTP_XOR_MULT_DOSStub_d4e9 {
  strings:
    $key_d4e9 = { 80 81 [2] f4 99 [2] b3 9b [2] f4 8a [2] ba 86 [2] b6 8c [2] a1 87 [2] ba c9 [2] 87 }

  condition:
    any of them
}