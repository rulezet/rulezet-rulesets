rule TTP_XOR_MULT_DOSStub_d664 {
  strings:
    $key_d664 = { 82 0c [2] f6 14 [2] b1 16 [2] f6 07 [2] b8 0b [2] b4 01 [2] a3 0a [2] b8 44 [2] 85 }

  condition:
    any of them
}