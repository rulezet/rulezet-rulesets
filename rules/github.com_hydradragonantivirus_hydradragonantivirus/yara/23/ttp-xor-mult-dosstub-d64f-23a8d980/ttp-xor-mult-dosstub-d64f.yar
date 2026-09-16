rule TTP_XOR_MULT_DOSStub_d64f {
  strings:
    $key_d64f = { 82 27 [2] f6 3f [2] b1 3d [2] f6 2c [2] b8 20 [2] b4 2a [2] a3 21 [2] b8 6f [2] 85 }

  condition:
    any of them
}