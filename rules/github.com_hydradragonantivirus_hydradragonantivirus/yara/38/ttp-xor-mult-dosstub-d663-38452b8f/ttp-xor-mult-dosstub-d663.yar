rule TTP_XOR_MULT_DOSStub_d663 {
  strings:
    $key_d663 = { 82 0b [2] f6 13 [2] b1 11 [2] f6 00 [2] b8 0c [2] b4 06 [2] a3 0d [2] b8 43 [2] 85 }

  condition:
    any of them
}