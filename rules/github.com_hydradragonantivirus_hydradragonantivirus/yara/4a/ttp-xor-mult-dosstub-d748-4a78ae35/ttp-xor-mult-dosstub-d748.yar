rule TTP_XOR_MULT_DOSStub_d748 {
  strings:
    $key_d748 = { 83 20 [2] f7 38 [2] b0 3a [2] f7 2b [2] b9 27 [2] b5 2d [2] a2 26 [2] b9 68 [2] 84 }

  condition:
    any of them
}