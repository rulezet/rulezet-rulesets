rule TTP_XOR_MULT_DOSStub_d628 {
  strings:
    $key_d628 = { 82 40 [2] f6 58 [2] b1 5a [2] f6 4b [2] b8 47 [2] b4 4d [2] a3 46 [2] b8 08 [2] 85 }

  condition:
    any of them
}