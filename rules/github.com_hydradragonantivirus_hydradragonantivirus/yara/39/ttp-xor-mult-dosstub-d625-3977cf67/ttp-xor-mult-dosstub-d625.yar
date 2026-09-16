rule TTP_XOR_MULT_DOSStub_d625 {
  strings:
    $key_d625 = { 82 4d [2] f6 55 [2] b1 57 [2] f6 46 [2] b8 4a [2] b4 40 [2] a3 4b [2] b8 05 [2] 85 }

  condition:
    any of them
}