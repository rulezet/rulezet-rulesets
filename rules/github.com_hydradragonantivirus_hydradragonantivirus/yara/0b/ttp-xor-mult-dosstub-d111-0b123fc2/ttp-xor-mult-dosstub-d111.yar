rule TTP_XOR_MULT_DOSStub_d111 {
  strings:
    $key_d111 = { 85 79 [2] f1 61 [2] b6 63 [2] f1 72 [2] bf 7e [2] b3 74 [2] a4 7f [2] bf 31 [2] 82 }

  condition:
    any of them
}