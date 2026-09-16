rule TTP_XOR_MULT_DOSStub_cc89 {
  strings:
    $key_cc89 = { 98 e1 [2] ec f9 [2] ab fb [2] ec ea [2] a2 e6 [2] ae ec [2] b9 e7 [2] a2 a9 [2] 9f }

  condition:
    any of them
}