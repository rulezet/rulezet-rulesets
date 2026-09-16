rule TTP_XOR_MULT_DOSStub_d71e {
  strings:
    $key_d71e = { 83 76 [2] f7 6e [2] b0 6c [2] f7 7d [2] b9 71 [2] b5 7b [2] a2 70 [2] b9 3e [2] 84 }

  condition:
    any of them
}