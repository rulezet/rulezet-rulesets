rule TTP_XOR_MULT_DOSStub_cc99 {
  strings:
    $key_cc99 = { 98 f1 [2] ec e9 [2] ab eb [2] ec fa [2] a2 f6 [2] ae fc [2] b9 f7 [2] a2 b9 [2] 9f }

  condition:
    any of them
}