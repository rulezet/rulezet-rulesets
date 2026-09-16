rule TTP_XOR_MULT_DOSStub_d43d {
  strings:
    $key_d43d = { 80 55 [2] f4 4d [2] b3 4f [2] f4 5e [2] ba 52 [2] b6 58 [2] a1 53 [2] ba 1d [2] 87 }

  condition:
    any of them
}