rule TTP_XOR_MULT_DOSStub_d00b {
  strings:
    $key_d00b = { 84 63 [2] f0 7b [2] b7 79 [2] f0 68 [2] be 64 [2] b2 6e [2] a5 65 [2] be 2b [2] 83 }

  condition:
    any of them
}