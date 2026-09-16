rule TTP_XOR_MULT_DOSStub_971b {
  strings:
    $key_971b = { c3 73 [2] b7 6b [2] f0 69 [2] b7 78 [2] f9 74 [2] f5 7e [2] e2 75 [2] f9 3b [2] c4 }

  condition:
    any of them
}