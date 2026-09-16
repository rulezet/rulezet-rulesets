rule TTP_XOR_MULT_DOSStub_d641 {
  strings:
    $key_d641 = { 82 29 [2] f6 31 [2] b1 33 [2] f6 22 [2] b8 2e [2] b4 24 [2] a3 2f [2] b8 61 [2] 85 }

  condition:
    any of them
}