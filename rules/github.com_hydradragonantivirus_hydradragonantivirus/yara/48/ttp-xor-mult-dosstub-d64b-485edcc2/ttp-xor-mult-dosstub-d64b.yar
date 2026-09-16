rule TTP_XOR_MULT_DOSStub_d64b {
  strings:
    $key_d64b = { 82 23 [2] f6 3b [2] b1 39 [2] f6 28 [2] b8 24 [2] b4 2e [2] a3 25 [2] b8 6b [2] 85 }

  condition:
    any of them
}