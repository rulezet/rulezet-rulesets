rule TTP_XOR_MULT_DOSStub_ccd5 {
  strings:
    $key_ccd5 = { 98 bd [2] ec a5 [2] ab a7 [2] ec b6 [2] a2 ba [2] ae b0 [2] b9 bb [2] a2 f5 [2] 9f }

  condition:
    any of them
}