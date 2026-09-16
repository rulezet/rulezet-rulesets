rule TTP_XOR_MULT_DOSStub_d47d {
  strings:
    $key_d47d = { 80 15 [2] f4 0d [2] b3 0f [2] f4 1e [2] ba 12 [2] b6 18 [2] a1 13 [2] ba 5d [2] 87 }

  condition:
    any of them
}