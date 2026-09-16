rule TTP_XOR_MULT_DOSStub_9ba5 {
  strings:
    $key_9ba5 = { cf cd [2] bb d5 [2] fc d7 [2] bb c6 [2] f5 ca [2] f9 c0 [2] ee cb [2] f5 85 [2] c8 }

  condition:
    any of them
}