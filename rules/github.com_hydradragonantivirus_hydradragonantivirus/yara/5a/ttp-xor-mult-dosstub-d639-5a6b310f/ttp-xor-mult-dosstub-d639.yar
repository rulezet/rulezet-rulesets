rule TTP_XOR_MULT_DOSStub_d639 {
  strings:
    $key_d639 = { 82 51 [2] f6 49 [2] b1 4b [2] f6 5a [2] b8 56 [2] b4 5c [2] a3 57 [2] b8 19 [2] 85 }

  condition:
    any of them
}