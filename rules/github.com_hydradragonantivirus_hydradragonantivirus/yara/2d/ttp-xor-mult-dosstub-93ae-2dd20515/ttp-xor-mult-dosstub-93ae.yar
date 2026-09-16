rule TTP_XOR_MULT_DOSStub_93ae {
  strings:
    $key_93ae = { c7 c6 [2] b3 de [2] f4 dc [2] b3 cd [2] fd c1 [2] f1 cb [2] e6 c0 [2] fd 8e [2] c0 }

  condition:
    any of them
}