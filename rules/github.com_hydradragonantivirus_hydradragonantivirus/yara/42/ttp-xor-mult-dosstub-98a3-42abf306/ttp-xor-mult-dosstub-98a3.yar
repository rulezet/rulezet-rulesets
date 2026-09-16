rule TTP_XOR_MULT_DOSStub_98a3 {
  strings:
    $key_98a3 = { cc cb [2] b8 d3 [2] ff d1 [2] b8 c0 [2] f6 cc [2] fa c6 [2] ed cd [2] f6 83 [2] cb }

  condition:
    any of them
}