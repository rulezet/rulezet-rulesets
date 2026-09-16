rule TTP_XOR_MULT_DOSStub_93a8 {
  strings:
    $key_93a8 = { c7 c0 [2] b3 d8 [2] f4 da [2] b3 cb [2] fd c7 [2] f1 cd [2] e6 c6 [2] fd 88 [2] c0 }

  condition:
    any of them
}