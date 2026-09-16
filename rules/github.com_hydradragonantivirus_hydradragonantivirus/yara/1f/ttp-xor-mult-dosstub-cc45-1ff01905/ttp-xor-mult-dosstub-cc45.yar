rule TTP_XOR_MULT_DOSStub_cc45 {
  strings:
    $key_cc45 = { 98 2d [2] ec 35 [2] ab 37 [2] ec 26 [2] a2 2a [2] ae 20 [2] b9 2b [2] a2 65 [2] 9f }

  condition:
    any of them
}