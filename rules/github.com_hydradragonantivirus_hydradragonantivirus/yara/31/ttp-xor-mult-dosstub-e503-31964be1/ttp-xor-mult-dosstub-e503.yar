rule TTP_XOR_MULT_DOSStub_e503 {
  strings:
    $key_e503 = { b1 6b [2] c5 73 [2] 82 71 [2] c5 60 [2] 8b 6c [2] 87 66 [2] 90 6d [2] 8b 23 [2] b6 }

  condition:
    any of them
}