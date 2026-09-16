rule TTP_XOR_MULT_DOSStub_d6e5 {
  strings:
    $key_d6e5 = { 82 8d [2] f6 95 [2] b1 97 [2] f6 86 [2] b8 8a [2] b4 80 [2] a3 8b [2] b8 c5 [2] 85 }

  condition:
    any of them
}