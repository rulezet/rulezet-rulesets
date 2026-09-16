rule TTP_XOR_MULT_DOSStub_96ed {
  strings:
    $key_96ed = { c2 85 [2] b6 9d [2] f1 9f [2] b6 8e [2] f8 82 [2] f4 88 [2] e3 83 [2] f8 cd [2] c5 }

  condition:
    any of them
}