rule TTP_XOR_MULT_DOSStub_d768 {
  strings:
    $key_d768 = { 83 00 [2] f7 18 [2] b0 1a [2] f7 0b [2] b9 07 [2] b5 0d [2] a2 06 [2] b9 48 [2] 84 }

  condition:
    any of them
}