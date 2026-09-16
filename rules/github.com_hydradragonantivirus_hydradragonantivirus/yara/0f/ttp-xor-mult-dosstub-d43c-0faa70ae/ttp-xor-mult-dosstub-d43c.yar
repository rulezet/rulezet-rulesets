rule TTP_XOR_MULT_DOSStub_d43c {
  strings:
    $key_d43c = { 80 54 [2] f4 4c [2] b3 4e [2] f4 5f [2] ba 53 [2] b6 59 [2] a1 52 [2] ba 1c [2] 87 }

  condition:
    any of them
}