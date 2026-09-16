rule TTP_XOR_MULT_DOSStub_e516 {
  strings:
    $key_e516 = { b1 7e [2] c5 66 [2] 82 64 [2] c5 75 [2] 8b 79 [2] 87 73 [2] 90 78 [2] 8b 36 [2] b6 }

  condition:
    any of them
}