rule TTP_XOR_MULT_DOSStub_d666 {
  strings:
    $key_d666 = { 82 0e [2] f6 16 [2] b1 14 [2] f6 05 [2] b8 09 [2] b4 03 [2] a3 08 [2] b8 46 [2] 85 }

  condition:
    any of them
}