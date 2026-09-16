rule TTP_XOR_MULT_DOSStub_93a5 {
  strings:
    $key_93a5 = { c7 cd [2] b3 d5 [2] f4 d7 [2] b3 c6 [2] fd ca [2] f1 c0 [2] e6 cb [2] fd 85 [2] c0 }

  condition:
    any of them
}