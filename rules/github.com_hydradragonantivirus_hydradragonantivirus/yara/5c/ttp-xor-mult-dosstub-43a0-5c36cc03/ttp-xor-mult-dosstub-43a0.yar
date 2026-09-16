rule TTP_XOR_MULT_DOSStub_43a0 {
  strings:
    $key_43a0 = { 17 c8 [2] 63 d0 [2] 24 d2 [2] 63 c3 [2] 2d cf [2] 21 c5 [2] 36 ce [2] 2d 80 [2] 10 }

  condition:
    any of them
}