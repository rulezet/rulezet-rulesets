rule TTP_XOR_MULT_DOSStub_d104 {
  strings:
    $key_d104 = { 85 6c [2] f1 74 [2] b6 76 [2] f1 67 [2] bf 6b [2] b3 61 [2] a4 6a [2] bf 24 [2] 82 }

  condition:
    any of them
}