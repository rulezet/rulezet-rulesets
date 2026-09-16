rule TTP_XOR_MULT_DOSStub_824b {
  strings:
    $key_824b = { d6 23 [2] a2 3b [2] e5 39 [2] a2 28 [2] ec 24 [2] e0 2e [2] f7 25 [2] ec 6b [2] d1 }

  condition:
    any of them
}