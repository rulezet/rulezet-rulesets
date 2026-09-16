rule TTP_XOR_MULT_DOSStub_d667 {
  strings:
    $key_d667 = { 82 0f [2] f6 17 [2] b1 15 [2] f6 04 [2] b8 08 [2] b4 02 [2] a3 09 [2] b8 47 [2] 85 }

  condition:
    any of them
}