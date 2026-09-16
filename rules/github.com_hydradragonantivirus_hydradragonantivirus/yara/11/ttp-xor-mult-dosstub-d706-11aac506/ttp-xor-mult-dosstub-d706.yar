rule TTP_XOR_MULT_DOSStub_d706 {
  strings:
    $key_d706 = { 83 6e [2] f7 76 [2] b0 74 [2] f7 65 [2] b9 69 [2] b5 63 [2] a2 68 [2] b9 26 [2] 84 }

  condition:
    any of them
}