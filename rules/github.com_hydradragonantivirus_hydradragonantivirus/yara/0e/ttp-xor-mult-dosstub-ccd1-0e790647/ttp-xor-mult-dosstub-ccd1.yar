rule TTP_XOR_MULT_DOSStub_ccd1 {
  strings:
    $key_ccd1 = { 98 b9 [2] ec a1 [2] ab a3 [2] ec b2 [2] a2 be [2] ae b4 [2] b9 bf [2] a2 f1 [2] 9f }

  condition:
    any of them
}