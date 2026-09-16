rule TTP_XOR_MULT_DOSStub_a71b {
  strings:
    $key_a71b = { f3 73 [2] 87 6b [2] c0 69 [2] 87 78 [2] c9 74 [2] c5 7e [2] d2 75 [2] c9 3b [2] f4 }

  condition:
    any of them
}