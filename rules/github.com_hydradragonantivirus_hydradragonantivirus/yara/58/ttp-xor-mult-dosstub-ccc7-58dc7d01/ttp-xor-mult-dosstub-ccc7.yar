rule TTP_XOR_MULT_DOSStub_ccc7 {
  strings:
    $key_ccc7 = { 98 af [2] ec b7 [2] ab b5 [2] ec a4 [2] a2 a8 [2] ae a2 [2] b9 a9 [2] a2 e7 [2] 9f }

  condition:
    any of them
}