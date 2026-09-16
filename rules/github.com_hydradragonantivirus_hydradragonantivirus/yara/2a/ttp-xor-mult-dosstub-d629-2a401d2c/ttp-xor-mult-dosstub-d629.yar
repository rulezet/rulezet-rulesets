rule TTP_XOR_MULT_DOSStub_d629 {
  strings:
    $key_d629 = { 82 41 [2] f6 59 [2] b1 5b [2] f6 4a [2] b8 46 [2] b4 4c [2] a3 47 [2] b8 09 [2] 85 }

  condition:
    any of them
}