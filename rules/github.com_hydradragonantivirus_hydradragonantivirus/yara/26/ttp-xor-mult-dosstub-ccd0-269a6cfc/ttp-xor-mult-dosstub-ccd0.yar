rule TTP_XOR_MULT_DOSStub_ccd0 {
  strings:
    $key_ccd0 = { 98 b8 [2] ec a0 [2] ab a2 [2] ec b3 [2] a2 bf [2] ae b5 [2] b9 be [2] a2 f0 [2] 9f }

  condition:
    any of them
}