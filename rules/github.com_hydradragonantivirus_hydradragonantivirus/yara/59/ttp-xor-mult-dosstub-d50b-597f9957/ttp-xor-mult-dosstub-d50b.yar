rule TTP_XOR_MULT_DOSStub_d50b {
  strings:
    $key_d50b = { 81 63 [2] f5 7b [2] b2 79 [2] f5 68 [2] bb 64 [2] b7 6e [2] a0 65 [2] bb 2b [2] 86 }

  condition:
    any of them
}