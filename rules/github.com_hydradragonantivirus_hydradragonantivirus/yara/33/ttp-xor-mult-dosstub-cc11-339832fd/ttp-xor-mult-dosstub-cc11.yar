rule TTP_XOR_MULT_DOSStub_cc11 {
  strings:
    $key_cc11 = { 98 79 [2] ec 61 [2] ab 63 [2] ec 72 [2] a2 7e [2] ae 74 [2] b9 7f [2] a2 31 [2] 9f }

  condition:
    any of them
}