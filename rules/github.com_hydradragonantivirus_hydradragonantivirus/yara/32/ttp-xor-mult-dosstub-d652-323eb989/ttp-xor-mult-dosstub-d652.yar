rule TTP_XOR_MULT_DOSStub_d652 {
  strings:
    $key_d652 = { 82 3a [2] f6 22 [2] b1 20 [2] f6 31 [2] b8 3d [2] b4 37 [2] a3 3c [2] b8 72 [2] 85 }

  condition:
    any of them
}