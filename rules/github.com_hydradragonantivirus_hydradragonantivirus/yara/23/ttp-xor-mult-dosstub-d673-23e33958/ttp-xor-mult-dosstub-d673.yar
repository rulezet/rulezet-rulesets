rule TTP_XOR_MULT_DOSStub_d673 {
  strings:
    $key_d673 = { 82 1b [2] f6 03 [2] b1 01 [2] f6 10 [2] b8 1c [2] b4 16 [2] a3 1d [2] b8 53 [2] 85 }

  condition:
    any of them
}