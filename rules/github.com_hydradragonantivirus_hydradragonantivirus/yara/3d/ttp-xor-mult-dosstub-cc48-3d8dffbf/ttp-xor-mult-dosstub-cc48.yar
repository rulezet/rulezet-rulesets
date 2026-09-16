rule TTP_XOR_MULT_DOSStub_cc48 {
  strings:
    $key_cc48 = { 98 20 [2] ec 38 [2] ab 3a [2] ec 2b [2] a2 27 [2] ae 2d [2] b9 26 [2] a2 68 [2] 9f }

  condition:
    any of them
}