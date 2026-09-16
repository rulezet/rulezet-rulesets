rule TTP_XOR_MULT_DOSStub_cc55 {
  strings:
    $key_cc55 = { 98 3d [2] ec 25 [2] ab 27 [2] ec 36 [2] a2 3a [2] ae 30 [2] b9 3b [2] a2 75 [2] 9f }

  condition:
    any of them
}