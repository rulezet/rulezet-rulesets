rule TTP_XOR_MULT_DOSStub_cc79 {
  strings:
    $key_cc79 = { 98 11 [2] ec 09 [2] ab 0b [2] ec 1a [2] a2 16 [2] ae 1c [2] b9 17 [2] a2 59 [2] 9f }

  condition:
    any of them
}