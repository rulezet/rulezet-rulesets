rule TTP_XOR_MULT_DOSStub_d41a {
  strings:
    $key_d41a = { 80 72 [2] f4 6a [2] b3 68 [2] f4 79 [2] ba 75 [2] b6 7f [2] a1 74 [2] ba 3a [2] 87 }

  condition:
    any of them
}