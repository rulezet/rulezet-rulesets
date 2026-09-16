rule TTP_XOR_MULT_DOSStub_ccc1 {
  strings:
    $key_ccc1 = { 98 a9 [2] ec b1 [2] ab b3 [2] ec a2 [2] a2 ae [2] ae a4 [2] b9 af [2] a2 e1 [2] 9f }

  condition:
    any of them
}