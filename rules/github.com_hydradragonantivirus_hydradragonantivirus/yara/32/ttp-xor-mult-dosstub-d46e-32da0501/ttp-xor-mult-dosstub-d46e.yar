rule TTP_XOR_MULT_DOSStub_d46e {
  strings:
    $key_d46e = { 80 06 [2] f4 1e [2] b3 1c [2] f4 0d [2] ba 01 [2] b6 0b [2] a1 00 [2] ba 4e [2] 87 }

  condition:
    any of them
}