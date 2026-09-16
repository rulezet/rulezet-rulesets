rule TTP_XOR_MULT_DOSStub_ccd9 {
  strings:
    $key_ccd9 = { 98 b1 [2] ec a9 [2] ab ab [2] ec ba [2] a2 b6 [2] ae bc [2] b9 b7 [2] a2 f9 [2] 9f }

  condition:
    any of them
}