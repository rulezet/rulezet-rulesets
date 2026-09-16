rule TTP_XOR_MULT_DOSStub_d40a {
  strings:
    $key_d40a = { 80 62 [2] f4 7a [2] b3 78 [2] f4 69 [2] ba 65 [2] b6 6f [2] a1 64 [2] ba 2a [2] 87 }

  condition:
    any of them
}