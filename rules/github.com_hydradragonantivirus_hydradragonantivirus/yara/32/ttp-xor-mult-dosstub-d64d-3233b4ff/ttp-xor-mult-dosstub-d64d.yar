rule TTP_XOR_MULT_DOSStub_d64d {
  strings:
    $key_d64d = { 82 25 [2] f6 3d [2] b1 3f [2] f6 2e [2] b8 22 [2] b4 28 [2] a3 23 [2] b8 6d [2] 85 }

  condition:
    any of them
}