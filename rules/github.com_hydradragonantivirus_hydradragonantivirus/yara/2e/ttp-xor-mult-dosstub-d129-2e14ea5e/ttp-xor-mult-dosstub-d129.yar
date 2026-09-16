rule TTP_XOR_MULT_DOSStub_d129 {
  strings:
    $key_d129 = { 85 41 [2] f1 59 [2] b6 5b [2] f1 4a [2] bf 46 [2] b3 4c [2] a4 47 [2] bf 09 [2] 82 }

  condition:
    any of them
}