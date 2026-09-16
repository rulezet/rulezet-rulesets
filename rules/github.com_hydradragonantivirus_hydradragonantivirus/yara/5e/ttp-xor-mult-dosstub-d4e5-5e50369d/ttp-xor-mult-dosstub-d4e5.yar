rule TTP_XOR_MULT_DOSStub_d4e5 {
  strings:
    $key_d4e5 = { 80 8d [2] f4 95 [2] b3 97 [2] f4 86 [2] ba 8a [2] b6 80 [2] a1 8b [2] ba c5 [2] 87 }

  condition:
    any of them
}