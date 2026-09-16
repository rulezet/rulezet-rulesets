rule TTP_XOR_MULT_DOSStub_d778 {
  strings:
    $key_d778 = { 83 10 [2] f7 08 [2] b0 0a [2] f7 1b [2] b9 17 [2] b5 1d [2] a2 16 [2] b9 58 [2] 84 }

  condition:
    any of them
}