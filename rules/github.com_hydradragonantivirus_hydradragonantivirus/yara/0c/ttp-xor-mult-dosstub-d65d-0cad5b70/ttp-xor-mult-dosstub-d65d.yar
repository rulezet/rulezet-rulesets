rule TTP_XOR_MULT_DOSStub_d65d {
  strings:
    $key_d65d = { 82 35 [2] f6 2d [2] b1 2f [2] f6 3e [2] b8 32 [2] b4 38 [2] a3 33 [2] b8 7d [2] 85 }

  condition:
    any of them
}