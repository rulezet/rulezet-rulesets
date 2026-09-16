rule TTP_XOR_MULT_DOSStub_d65f {
  strings:
    $key_d65f = { 82 37 [2] f6 2f [2] b1 2d [2] f6 3c [2] b8 30 [2] b4 3a [2] a3 31 [2] b8 7f [2] 85 }

  condition:
    any of them
}