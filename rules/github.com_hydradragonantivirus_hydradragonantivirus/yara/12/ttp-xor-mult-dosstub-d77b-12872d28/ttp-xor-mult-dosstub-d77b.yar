rule TTP_XOR_MULT_DOSStub_d77b {
  strings:
    $key_d77b = { 83 13 [2] f7 0b [2] b0 09 [2] f7 18 [2] b9 14 [2] b5 1e [2] a2 15 [2] b9 5b [2] 84 }

  condition:
    any of them
}