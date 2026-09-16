rule TTP_XOR_MULT_DOSStub_cc63 {
  strings:
    $key_cc63 = { 98 0b [2] ec 13 [2] ab 11 [2] ec 00 [2] a2 0c [2] ae 06 [2] b9 0d [2] a2 43 [2] 9f }

  condition:
    any of them
}