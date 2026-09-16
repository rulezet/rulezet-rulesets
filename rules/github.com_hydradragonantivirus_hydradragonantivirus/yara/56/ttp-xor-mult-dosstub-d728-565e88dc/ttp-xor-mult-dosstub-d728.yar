rule TTP_XOR_MULT_DOSStub_d728 {
  strings:
    $key_d728 = { 83 40 [2] f7 58 [2] b0 5a [2] f7 4b [2] b9 47 [2] b5 4d [2] a2 46 [2] b9 08 [2] 84 }

  condition:
    any of them
}