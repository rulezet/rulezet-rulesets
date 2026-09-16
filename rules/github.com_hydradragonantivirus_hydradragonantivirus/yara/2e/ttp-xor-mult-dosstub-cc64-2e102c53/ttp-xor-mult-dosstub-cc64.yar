rule TTP_XOR_MULT_DOSStub_cc64 {
  strings:
    $key_cc64 = { 98 0c [2] ec 14 [2] ab 16 [2] ec 07 [2] a2 0b [2] ae 01 [2] b9 0a [2] a2 44 [2] 9f }

  condition:
    any of them
}