rule TTP_XOR_MULT_DOSStub_83eb {
  strings:
    $key_83eb = { d7 83 [2] a3 9b [2] e4 99 [2] a3 88 [2] ed 84 [2] e1 8e [2] f6 85 [2] ed cb [2] d0 }

  condition:
    any of them
}