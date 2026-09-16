rule TTP_XOR_MULT_DOSStub_d662 {
  strings:
    $key_d662 = { 82 0a [2] f6 12 [2] b1 10 [2] f6 01 [2] b8 0d [2] b4 07 [2] a3 0c [2] b8 42 [2] 85 }

  condition:
    any of them
}