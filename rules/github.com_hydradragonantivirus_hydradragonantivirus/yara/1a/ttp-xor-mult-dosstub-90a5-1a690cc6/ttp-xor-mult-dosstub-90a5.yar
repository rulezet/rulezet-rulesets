rule TTP_XOR_MULT_DOSStub_90a5 {
  strings:
    $key_90a5 = { c4 cd [2] b0 d5 [2] f7 d7 [2] b0 c6 [2] fe ca [2] f2 c0 [2] e5 cb [2] fe 85 [2] c3 }

  condition:
    any of them
}