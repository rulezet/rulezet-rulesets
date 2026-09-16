rule TTP_XOR_MULT_DOSStub_d403 {
  strings:
    $key_d403 = { 80 6b [2] f4 73 [2] b3 71 [2] f4 60 [2] ba 6c [2] b6 66 [2] a1 6d [2] ba 23 [2] 87 }

  condition:
    any of them
}