rule TTP_XOR_MULT_DOSStub_d4ee {
  strings:
    $key_d4ee = { 80 86 [2] f4 9e [2] b3 9c [2] f4 8d [2] ba 81 [2] b6 8b [2] a1 80 [2] ba ce [2] 87 }

  condition:
    any of them
}