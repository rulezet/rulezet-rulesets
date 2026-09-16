rule TTP_XOR_MULT_DOSStub_d44c {
  strings:
    $key_d44c = { 80 24 [2] f4 3c [2] b3 3e [2] f4 2f [2] ba 23 [2] b6 29 [2] a1 22 [2] ba 6c [2] 87 }

  condition:
    any of them
}