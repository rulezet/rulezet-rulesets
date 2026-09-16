rule TTP_XOR_MULT_DOSStub_d44f {
  strings:
    $key_d44f = { 80 27 [2] f4 3f [2] b3 3d [2] f4 2c [2] ba 20 [2] b6 2a [2] a1 21 [2] ba 6f [2] 87 }

  condition:
    any of them
}