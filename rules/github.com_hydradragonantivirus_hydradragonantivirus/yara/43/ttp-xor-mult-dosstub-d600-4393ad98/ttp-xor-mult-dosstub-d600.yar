rule TTP_XOR_MULT_DOSStub_d600 {
  strings:
    $key_d600 = { 82 68 [2] f6 70 [2] b1 72 [2] f6 63 [2] b8 6f [2] b4 65 [2] a3 6e [2] b8 20 [2] 85 }

  condition:
    any of them
}