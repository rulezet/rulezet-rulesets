rule TTP_XOR_MULT_DOSStub_d617 {
  strings:
    $key_d617 = { 82 7f [2] f6 67 [2] b1 65 [2] f6 74 [2] b8 78 [2] b4 72 [2] a3 79 [2] b8 37 [2] 85 }

  condition:
    any of them
}