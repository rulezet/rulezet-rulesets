rule TTP_XOR_MULT_DOSStub_d6e8 {
  strings:
    $key_d6e8 = { 82 80 [2] f6 98 [2] b1 9a [2] f6 8b [2] b8 87 [2] b4 8d [2] a3 86 [2] b8 c8 [2] 85 }

  condition:
    any of them
}