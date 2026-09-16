rule TTP_XOR_MULT_DOSStub_d753 {
  strings:
    $key_d753 = { 83 3b [2] f7 23 [2] b0 21 [2] f7 30 [2] b9 3c [2] b5 36 [2] a2 3d [2] b9 73 [2] 84 }

  condition:
    any of them
}