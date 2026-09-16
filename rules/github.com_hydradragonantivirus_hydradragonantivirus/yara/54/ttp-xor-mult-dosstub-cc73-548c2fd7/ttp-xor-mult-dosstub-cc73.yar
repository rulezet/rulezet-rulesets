rule TTP_XOR_MULT_DOSStub_cc73 {
  strings:
    $key_cc73 = { 98 1b [2] ec 03 [2] ab 01 [2] ec 10 [2] a2 1c [2] ae 16 [2] b9 1d [2] a2 53 [2] 9f }

  condition:
    any of them
}