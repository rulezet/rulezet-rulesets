rule TTP_XOR_MULT_DOSStub_cc92 {
  strings:
    $key_cc92 = { 98 fa [2] ec e2 [2] ab e0 [2] ec f1 [2] a2 fd [2] ae f7 [2] b9 fc [2] a2 b2 [2] 9f }

  condition:
    any of them
}