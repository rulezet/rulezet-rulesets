rule TTP_XOR_MULT_DOSStub_d624 {
  strings:
    $key_d624 = { 82 4c [2] f6 54 [2] b1 56 [2] f6 47 [2] b8 4b [2] b4 41 [2] a3 4a [2] b8 04 [2] 85 }

  condition:
    any of them
}