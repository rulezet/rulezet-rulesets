rule TTP_XOR_MULT_DOSStub_d67e {
  strings:
    $key_d67e = { 82 16 [2] f6 0e [2] b1 0c [2] f6 1d [2] b8 11 [2] b4 1b [2] a3 10 [2] b8 5e [2] 85 }

  condition:
    any of them
}