rule TTP_XOR_MULT_DOSStub_cc61 {
  strings:
    $key_cc61 = { 98 09 [2] ec 11 [2] ab 13 [2] ec 02 [2] a2 0e [2] ae 04 [2] b9 0f [2] a2 41 [2] 9f }

  condition:
    any of them
}