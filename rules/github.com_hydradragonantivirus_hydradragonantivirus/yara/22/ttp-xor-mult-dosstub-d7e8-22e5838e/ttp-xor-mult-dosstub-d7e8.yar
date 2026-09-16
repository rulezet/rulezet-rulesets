rule TTP_XOR_MULT_DOSStub_d7e8 {
  strings:
    $key_d7e8 = { 83 80 [2] f7 98 [2] b0 9a [2] f7 8b [2] b9 87 [2] b5 8d [2] a2 86 [2] b9 c8 [2] 84 }

  condition:
    any of them
}