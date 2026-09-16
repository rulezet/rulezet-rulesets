rule TTP_XOR_MULT_DOSStub_d648 {
  strings:
    $key_d648 = { 82 20 [2] f6 38 [2] b1 3a [2] f6 2b [2] b8 27 [2] b4 2d [2] a3 26 [2] b8 68 [2] 85 }

  condition:
    any of them
}