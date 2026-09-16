rule TTP_XOR_MULT_DOSStub_aba5 {
  strings:
    $key_aba5 = { ff cd [2] 8b d5 [2] cc d7 [2] 8b c6 [2] c5 ca [2] c9 c0 [2] de cb [2] c5 85 [2] f8 }

  condition:
    any of them
}