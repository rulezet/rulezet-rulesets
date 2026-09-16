rule TTP_XOR_MULT_DOSStub_d64e {
  strings:
    $key_d64e = { 82 26 [2] f6 3e [2] b1 3c [2] f6 2d [2] b8 21 [2] b4 2b [2] a3 20 [2] b8 6e [2] 85 }

  condition:
    any of them
}