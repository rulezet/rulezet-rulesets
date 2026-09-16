rule TTP_XOR_MULT_DOSStub_cc12 {
  strings:
    $key_cc12 = { 98 7a [2] ec 62 [2] ab 60 [2] ec 71 [2] a2 7d [2] ae 77 [2] b9 7c [2] a2 32 [2] 9f }

  condition:
    any of them
}