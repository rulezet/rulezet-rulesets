rule TTP_XOR_MULT_DOSStub_cc98 {
  strings:
    $key_cc98 = { 98 f0 [2] ec e8 [2] ab ea [2] ec fb [2] a2 f7 [2] ae fd [2] b9 f6 [2] a2 b8 [2] 9f }

  condition:
    any of them
}