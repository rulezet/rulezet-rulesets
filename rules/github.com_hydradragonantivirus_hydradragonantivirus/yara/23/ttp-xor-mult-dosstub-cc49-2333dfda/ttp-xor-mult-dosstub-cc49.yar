rule TTP_XOR_MULT_DOSStub_cc49 {
  strings:
    $key_cc49 = { 98 21 [2] ec 39 [2] ab 3b [2] ec 2a [2] a2 26 [2] ae 2c [2] b9 27 [2] a2 69 [2] 9f }

  condition:
    any of them
}