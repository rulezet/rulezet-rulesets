rule TTP_XOR_MULT_DOSStub_d6e0 {
  strings:
    $key_d6e0 = { 82 88 [2] f6 90 [2] b1 92 [2] f6 83 [2] b8 8f [2] b4 85 [2] a3 8e [2] b8 c0 [2] 85 }

  condition:
    any of them
}