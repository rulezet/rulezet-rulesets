rule TTP_XOR_MULT_DOSStub_d75b {
  strings:
    $key_d75b = { 83 33 [2] f7 2b [2] b0 29 [2] f7 38 [2] b9 34 [2] b5 3e [2] a2 35 [2] b9 7b [2] 84 }

  condition:
    any of them
}