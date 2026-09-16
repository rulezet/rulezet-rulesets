rule TTP_XOR_MULT_DOSStub_dadb {
  strings:
    $key_dadb = { 8e b3 [2] fa ab [2] bd a9 [2] fa b8 [2] b4 b4 [2] b8 be [2] af b5 [2] b4 fb [2] 89 }

  condition:
    any of them
}