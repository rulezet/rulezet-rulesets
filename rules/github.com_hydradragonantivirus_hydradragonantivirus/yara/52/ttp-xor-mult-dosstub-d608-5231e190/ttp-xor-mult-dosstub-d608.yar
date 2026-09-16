rule TTP_XOR_MULT_DOSStub_d608 {
  strings:
    $key_d608 = { 82 60 [2] f6 78 [2] b1 7a [2] f6 6b [2] b8 67 [2] b4 6d [2] a3 66 [2] b8 28 [2] 85 }

  condition:
    any of them
}