rule TTP_XOR_MULT_DOSStub_d70b {
  strings:
    $key_d70b = { 83 63 [2] f7 7b [2] b0 79 [2] f7 68 [2] b9 64 [2] b5 6e [2] a2 65 [2] b9 2b [2] 84 }

  condition:
    any of them
}