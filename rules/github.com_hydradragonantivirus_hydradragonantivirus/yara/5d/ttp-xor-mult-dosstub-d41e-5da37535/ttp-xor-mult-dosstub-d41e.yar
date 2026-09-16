rule TTP_XOR_MULT_DOSStub_d41e {
  strings:
    $key_d41e = { 80 76 [2] f4 6e [2] b3 6c [2] f4 7d [2] ba 71 [2] b6 7b [2] a1 70 [2] ba 3e [2] 87 }

  condition:
    any of them
}