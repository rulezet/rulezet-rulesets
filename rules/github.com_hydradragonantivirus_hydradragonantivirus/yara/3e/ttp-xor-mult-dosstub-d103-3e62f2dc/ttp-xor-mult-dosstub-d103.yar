rule TTP_XOR_MULT_DOSStub_d103 {
  strings:
    $key_d103 = { 85 6b [2] f1 73 [2] b6 71 [2] f1 60 [2] bf 6c [2] b3 66 [2] a4 6d [2] bf 23 [2] 82 }

  condition:
    any of them
}