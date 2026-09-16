rule TTP_XOR_MULT_DOSStub_cc95 {
  strings:
    $key_cc95 = { 98 fd [2] ec e5 [2] ab e7 [2] ec f6 [2] a2 fa [2] ae f0 [2] b9 fb [2] a2 b5 [2] 9f }

  condition:
    any of them
}