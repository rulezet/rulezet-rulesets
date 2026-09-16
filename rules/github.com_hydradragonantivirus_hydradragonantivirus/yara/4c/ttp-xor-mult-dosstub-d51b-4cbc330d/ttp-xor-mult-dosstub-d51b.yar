rule TTP_XOR_MULT_DOSStub_d51b {
  strings:
    $key_d51b = { 81 73 [2] f5 6b [2] b2 69 [2] f5 78 [2] bb 74 [2] b7 7e [2] a0 75 [2] bb 3b [2] 86 }

  condition:
    any of them
}