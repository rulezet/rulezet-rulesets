rule TTP_XOR_MULT_DOSStub_d45f {
  strings:
    $key_d45f = { 80 37 [2] f4 2f [2] b3 2d [2] f4 3c [2] ba 30 [2] b6 3a [2] a1 31 [2] ba 7f [2] 87 }

  condition:
    any of them
}