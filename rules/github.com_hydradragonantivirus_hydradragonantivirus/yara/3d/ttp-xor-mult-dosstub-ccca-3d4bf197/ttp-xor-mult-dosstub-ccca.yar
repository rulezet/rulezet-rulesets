rule TTP_XOR_MULT_DOSStub_ccca {
  strings:
    $key_ccca = { 98 a2 [2] ec ba [2] ab b8 [2] ec a9 [2] a2 a5 [2] ae af [2] b9 a4 [2] a2 ea [2] 9f }

  condition:
    any of them
}