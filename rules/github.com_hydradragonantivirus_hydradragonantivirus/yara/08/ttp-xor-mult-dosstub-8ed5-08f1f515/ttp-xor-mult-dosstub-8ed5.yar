rule TTP_XOR_MULT_DOSStub_8ed5 {
  strings:
    $key_8ed5 = { da bd [2] ae a5 [2] e9 a7 [2] ae b6 [2] e0 ba [2] ec b0 [2] fb bb [2] e0 f5 [2] dd }

  condition:
    any of them
}