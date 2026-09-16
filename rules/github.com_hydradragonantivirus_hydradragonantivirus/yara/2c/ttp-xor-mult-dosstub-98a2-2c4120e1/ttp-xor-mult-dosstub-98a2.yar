rule TTP_XOR_MULT_DOSStub_98a2 {
  strings:
    $key_98a2 = { cc ca [2] b8 d2 [2] ff d0 [2] b8 c1 [2] f6 cd [2] fa c7 [2] ed cc [2] f6 82 [2] cb }

  condition:
    any of them
}