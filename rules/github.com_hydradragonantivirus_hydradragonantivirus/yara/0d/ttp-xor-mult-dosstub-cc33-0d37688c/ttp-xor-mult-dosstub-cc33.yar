rule TTP_XOR_MULT_DOSStub_cc33 {
  strings:
    $key_cc33 = { 98 5b [2] ec 43 [2] ab 41 [2] ec 50 [2] a2 5c [2] ae 56 [2] b9 5d [2] a2 13 [2] 9f }

  condition:
    any of them
}