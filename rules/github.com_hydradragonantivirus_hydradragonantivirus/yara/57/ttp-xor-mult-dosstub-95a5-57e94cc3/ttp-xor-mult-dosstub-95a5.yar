rule TTP_XOR_MULT_DOSStub_95a5 {
  strings:
    $key_95a5 = { c1 cd [2] b5 d5 [2] f2 d7 [2] b5 c6 [2] fb ca [2] f7 c0 [2] e0 cb [2] fb 85 [2] c6 }

  condition:
    any of them
}