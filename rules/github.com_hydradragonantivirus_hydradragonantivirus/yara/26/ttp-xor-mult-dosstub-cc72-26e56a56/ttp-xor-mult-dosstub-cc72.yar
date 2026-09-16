rule TTP_XOR_MULT_DOSStub_cc72 {
  strings:
    $key_cc72 = { 98 1a [2] ec 02 [2] ab 00 [2] ec 11 [2] a2 1d [2] ae 17 [2] b9 1c [2] a2 52 [2] 9f }

  condition:
    any of them
}