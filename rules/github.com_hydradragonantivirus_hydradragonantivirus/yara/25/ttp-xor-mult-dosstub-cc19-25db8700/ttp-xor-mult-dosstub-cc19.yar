rule TTP_XOR_MULT_DOSStub_cc19 {
  strings:
    $key_cc19 = { 98 71 [2] ec 69 [2] ab 6b [2] ec 7a [2] a2 76 [2] ae 7c [2] b9 77 [2] a2 39 [2] 9f }

  condition:
    any of them
}